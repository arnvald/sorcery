module Sorcery
  module Model
    module Adapters
      module Mongoid
        def self.included(klass)
          klass.extend ClassMethods
          klass.send(:include, InstanceMethods)

          klass.class_eval do
            sorcery_config.username_attribute_names.each do |username|
              field username,         :type => String
            end
            field sorcery_config.email_attribute_name,            :type => String unless sorcery_config.username_attribute_names.include?(sorcery_config.email_attribute_name)
            field sorcery_config.crypted_password_attribute_name, :type => String
            field sorcery_config.salt_attribute_name,             :type => String
          end
        end

        module InstanceMethods
          def increment(attr)
            self.inc(attr, 1)
          end

          def update_many_attributes(attrs)
            attrs.each do |name, value|
              attrs[name] = value.utc if value.is_a?(ActiveSupport::TimeWithZone)
              self.send(:"#{name}=", value)
            end
            self.class.where(:_id => self.id).update_all(attrs)
          end

          def update_single_attribute(name, value)
            update_many_attributes(name => value)
          end

          def sorcery_save(options = {})
            mthd = options.delete(:raise_on_failure) ? :save! : :save
            self.send(mthd, options)
          end
        end

        module ClassMethods
          def credential_regex(credential)
            return { :$regex =>  /^#{Regexp.escape(credential)}$/i  } if (@sorcery_config.downcase_username_before_authenticating)
            credential
          end

          def find_by_credentials(credentials)
            @sorcery_config.username_attribute_names.each do |attribute|
              @user = where(attribute => credential_regex(credentials[0])).first
              break if @user
            end
            @user
          end

          def find_by_provider_and_uid(provider, uid)
            where(@user_klass.sorcery_config.provider_attribute_name => provider, @user_klass.sorcery_config.provider_uid_attribute_name => uid).first
          end

          def find_by_id(id)
            find(id)
          rescue ::Mongoid::Errors::DocumentNotFound
            nil
          end

          def find_by_activation_token(token)
            where(sorcery_config.activation_token_attribute_name => token).first
          end

          def find_by_remember_me_token(token)
            where(sorcery_config.remember_me_token_attribute_name => token).first
          end

          def find_by_username(username)
            query = sorcery_config.username_attribute_names.map {|name| {name => username}}
            any_of(*query).first
          end

          def transaction(&blk)
            tap(&blk)
          end

          def find_by_sorcery_token(token_attr_name, token)
            where(token_attr_name => token).first
          end

          def find_by_email(email)
            where(sorcery_config.email_attribute_name => email).first
          end

          def get_current_users
            config = sorcery_config
            where(config.last_activity_at_attribute_name.ne => nil) \
            .where("this.#{config.last_logout_at_attribute_name} == null || this.#{config.last_activity_at_attribute_name} > this.#{config.last_logout_at_attribute_name}") \
            .where(config.last_activity_at_attribute_name.gt => config.activity_timeout.seconds.ago.utc).order_by([:_id,:asc])
          end

          # ===========================
          # = Submodules initializers =
          # ===========================

          def init_sorcery_brute_force_protection
            field sorcery_config.failed_logins_count_attribute_name,  :type => Integer, :default => 0
            field sorcery_config.lock_expires_at_attribute_name,      :type => Time
            field sorcery_config.unlock_token_attribute_name,         :type => String
          end

          def init_sorcery_user_activation
            field sorcery_config.activation_state_attribute_name,            :type => String
            field sorcery_config.activation_token_attribute_name,            :type => String
            field sorcery_config.activation_token_expires_at_attribute_name, :type => Time

            before_create :setup_activation, :if => Proc.new { |user| user.send(sorcery_config.password_attribute_name).present? }
            after_create  :send_activation_needed_email!, :if => :send_activation_needed_email?
          end

          def init_sorcery_activity_logging
            field sorcery_config.last_login_at_attribute_name,    :type => Time
            field sorcery_config.last_logout_at_attribute_name,   :type => Time
            field sorcery_config.last_activity_at_attribute_name, :type => Time
            field sorcery_config.last_login_from_ip_address_name, :type => String
          end

          def init_sorcery_remember_me
            field sorcery_config.remember_me_token_attribute_name,            :type => String
            field sorcery_config.remember_me_token_expires_at_attribute_name, :type => Time
          end

          def init_sorcery_reset_password
            field sorcery_config.reset_password_token_attribute_name,             :type => String
            field sorcery_config.reset_password_token_expires_at_attribute_name,  :type => Time
            field sorcery_config.reset_password_email_sent_at_attribute_name,     :type => Time
          end

          def init_sorcery_hooks
            attr_accessor @sorcery_config.password_attribute_name
            before_save :encrypt_password, :if => Proc.new { |record|
              record.send(sorcery_config.password_attribute_name).present?
            }
            after_save :clear_virtual_password, :if => Proc.new { |record|
              record.send(sorcery_config.password_attribute_name).present?
            }
          end
        end
      end
    end
  end
end
