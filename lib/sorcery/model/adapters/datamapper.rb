module Sorcery
  module Model
    module Adapters
      module DataMapper
        def self.included(klass)
          klass.extend ClassMethods
          klass.send(:include, InstanceMethods)

          klass.class_eval do
            sorcery_config.username_attribute_names.each do |username|
              property username, String, :length => 255
            end
            unless sorcery_config.username_attribute_names.include?(sorcery_config.email_attribute_name)
              property sorcery_config.email_attribute_name, String, :length => 255
            end
            property sorcery_config.crypted_password_attribute_name, String, :length => 255
            property sorcery_config.salt_attribute_name, String, :length => 255
          end

        end

        module InstanceMethods
          def increment(attr)
            self[attr] ||= 0
            self[attr] += 1
            self
          end

          def update_many_attributes(attrs)
            attrs.each do |name, value|
              value = value.utc if value.is_a?(ActiveSupport::TimeWithZone)
              self.send(:"#{name}=", value)
            end
            self.class.get(self.id).update(attrs)
          end

          def update_single_attribute(name, value)
            update_many_attributes(name => value)
          end

          def sorcery_save(options = {})
            if options.key?(:validate) && ! options[:validate]
              save!
            else
              save
            end
          end
        end

        module ClassMethods
          def find(id)
            get(id)
          end

          def delete_all
            destroy
          end

          # NOTE
          # DM Adapter dependent
          # DM creates MySQL tables case insensitive by default
          # http://datamapper.lighthouseapp.com/projects/20609-datamapper/tickets/1105
          def find_by_credentials(credentials)
            credential = credentials[0].dup
            credential.downcase! if @sorcery_config.downcase_username_before_authenticating
            @sorcery_config.username_attribute_names.each do |name|
              @user = first(name => credential)
              break if @user
            end
            !!@user ? get(@user.id) : nil
          end

          def find_by_provider_and_uid(provider, uid)
            @user_klass ||= ::Sorcery::Controller::Config.user_class.to_s.constantize
            user = first(@user_klass.sorcery_config.provider_attribute_name => provider, @user_klass.sorcery_config.provider_uid_attribute_name => uid)
            !!user ? get(user.id) : nil
          end

          def find_by_id(id)
            find(id)
          rescue ::DataMapper::ObjectNotFoundError
            nil
          end

          def find_by_activation_token(token)
            user = first(sorcery_config.activation_token_attribute_name => token)
            !!user ? get(user.id) : nil
          end

          def find_by_remember_me_token(token)
            user = first(sorcery_config.remember_me_token_attribute_name => token)
            !!user ? get(user.id) : nil
          end

          def find_by_username(username)
            user = nil
            sorcery_config.username_attribute_names.each do |name|
              user = first(name => username)
              break if user
            end
            !!user ? get(user.id) : nil
          end

          def transaction(&blk)
            tap(&blk)
          end

          def find_by_sorcery_token(token_attr_name, token)
            user = first(token_attr_name => token)
            !!user ? get(user.id) : nil
          end

          def find_by_email(email)
            user = first(sorcery_config.email_attribute_name => email)
            !!user ? get(user.id) : nil
          end

          # NOTE
          # DM Adapter dependent
          def get_current_users
            unless self.repository.adapter.is_a?(::DataMapper::Adapters::MysqlAdapter)
              raise 'Unsupported DataMapper Adapter'
            end
            config = sorcery_config
            ret = all(config.last_logout_at_attribute_name => nil) |
                  all(config.last_activity_at_attribute_name.gt => config.last_logout_at_attribute_name)
            ret = ret.all(config.last_activity_at_attribute_name.not => nil)
            ret = ret.all(config.last_activity_at_attribute_name.gt => config.activity_timeout.seconds.ago.utc)
            ret
          end

          # ===========================
          # = Submodules initializers =
          # ===========================

          def init_sorcery_brute_force_protection
            property sorcery_config.failed_logins_count_attribute_name, Integer, :default => 0
            property sorcery_config.lock_expires_at_attribute_name,     Time
            property sorcery_config.unlock_token_attribute_name,        String
            [sorcery_config.lock_expires_at_attribute_name].each do |sym|
              alias_method "orig_#{sym}", sym
              define_method(sym) do
                t = send("orig_#{sym}")
                t && Time.new(t.year, t.month, t.day, t.hour, t.min, t.sec, 0)
              end
            end
          end

          def init_sorcery_user_activation
            property sorcery_config.activation_state_attribute_name,            String
            property sorcery_config.activation_token_attribute_name,            String
            property sorcery_config.activation_token_expires_at_attribute_name, Time
            [sorcery_config.activation_token_expires_at_attribute_name].each do |sym|
              alias_method "orig_#{sym}", sym
              define_method(sym) do
                t = send("orig_#{sym}")
                t && Time.new(t.year, t.month, t.day, t.hour, t.min, t.sec, 0)
              end
            end

            before :valid? do
              setup_activation if self.send(sorcery_config.password_attribute_name).present?
            end
            after :create do
              send_activation_needed_email!  if send_activation_needed_email?
            end
          end

          def init_sorcery_activity_logging
            unless repository.adapter.is_a?(::DataMapper::Adapters::MysqlAdapter)
              raise 'Unsupported DataMapper Adapter'
            end

            property sorcery_config.last_login_at_attribute_name,    Time
            property sorcery_config.last_logout_at_attribute_name,   Time
            property sorcery_config.last_activity_at_attribute_name, Time
            property sorcery_config.last_login_from_ip_address_name, String
            # Workaround local timezone retrieval problem NOTE dm-core issue #193
            [sorcery_config.last_login_at_attribute_name,
             sorcery_config.last_logout_at_attribute_name,
             sorcery_config.last_activity_at_attribute_name].each do |sym|
               alias_method "orig_#{sym}", sym
               define_method(sym) do
                 t = send("orig_#{sym}")
                 t && Time.new(t.year, t.month, t.day, t.hour, t.min, t.sec, 0)
               end
             end
          end

          def init_sorcery_remember_me
            property sorcery_config.remember_me_token_attribute_name,            String
            property sorcery_config.remember_me_token_expires_at_attribute_name, Time
            [sorcery_config.remember_me_token_expires_at_attribute_name].each do |sym|
              alias_method "orig_#{sym}", sym
              define_method(sym) do
                t = send("orig_#{sym}")
                t && Time.new(t.year, t.month, t.day, t.hour, t.min, t.sec, 0)
              end
            end
          end

          def init_sorcery_reset_password
            property sorcery_config.reset_password_token_attribute_name,            String
            property sorcery_config.reset_password_token_expires_at_attribute_name, Time
            property sorcery_config.reset_password_email_sent_at_attribute_name,    Time
            [sorcery_config.reset_password_token_expires_at_attribute_name,
             sorcery_config.reset_password_email_sent_at_attribute_name].each do |sym|
               alias_method "orig_#{sym}", sym
               define_method(sym) do
                 t = send("orig_#{sym}")
                 t && Time.new(t.year, t.month, t.day, t.hour, t.min, t.sec, 0)
               end
            end
          end

          def init_sorcery_hooks
            before :valid? do
              encrypt_password if self.send(sorcery_config.password_attribute_name).present?
            end
            after :save do
              clear_virtual_password if self.send(sorcery_config.password_attribute_name).present?
            end
          end

        end
      end
    end
  end
end
