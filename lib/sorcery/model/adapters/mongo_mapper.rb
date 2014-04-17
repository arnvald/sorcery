module Sorcery
  module Model
    module Adapters
      module MongoMapper
        extend ActiveSupport::Concern

        included do
          include Sorcery::Model

          sorcery_config.username_attribute_names.each do |username|
            key username, String
          end
          key sorcery_config.email_attribute_name, String unless sorcery_config.username_attribute_names.include?(sorcery_config.email_attribute_name)
          key sorcery_config.crypted_password_attribute_name, String
          key sorcery_config.salt_attribute_name, String
        end

        def increment(attr)
          self.class.increment(id, attr => 1)
        end

        def sorcery_save(options = {})
          if options.delete(:raise_on_failure) && options[:validate] != false
            save! options
          else
            save options
          end
        end

        def update_many_attributes(attrs)
          update_attributes(attrs)
        end

        module ClassMethods
          def credential_regex(credential)
            return { :$regex =>  /^#{Regexp.escape(credential)}$/i  }  if (@sorcery_config.downcase_username_before_authenticating)
            return credential
          end

          def find_by_credentials(credentials)
            @sorcery_config.username_attribute_names.each do |attribute|
              @user = where(attribute => credential_regex(credentials[0])).first
              break if @user
            end
            @user
          end

          def find_by_id(id)
            find(id)
          end

          def find_by_activation_token(token)
            where(sorcery_config.activation_token_attribute_name => token).first
          end

          def transaction(&blk)
            tap(&blk)
          end

          def find_by_sorcery_token(token_attr_name, token)
            where(token_attr_name => token).first
          end

          # ===========================
          # = Submodules initializers =
          # ===========================

          def init_sorcery_brute_force_protection
            key sorcery_config.failed_logins_count_attribute_name, Integer, :default => 0
            key sorcery_config.lock_expires_at_attribute_name, Time
            key sorcery_config.unlock_token_attribute_name, String
          end

          def init_sorcery_user_activation
            key sorcery_config.activation_state_attribute_name, String
            key sorcery_config.activation_token_attribute_name, String
            key sorcery_config.activation_token_expires_at_attribute_name, Time

            before_create :setup_activation, :if => Proc.new { |user| user.send(sorcery_config.password_attribute_name).present? }
            after_create  :send_activation_needed_email!, :if => :send_activation_needed_email?
          end

          def init_sorcery_remember_me
            key sorcery_config.remember_me_token_attribute_name, String
            key sorcery_config.remember_me_token_expires_at_attribute_name, Time
          end

          def init_sorcery_reset_password
            key sorcery_config.reset_password_token_attribute_name, String
            key sorcery_config.reset_password_token_expires_at_attribute_name, Time
            key sorcery_config.reset_password_email_sent_at_attribute_name, Time
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
