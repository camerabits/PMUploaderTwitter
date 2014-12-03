#!/usr/bin/env ruby
##############################################################################
# Copyright (c) 2014 Camera Bits, Inc.  All rights reserved.
##############################################################################
TEMPLATE_DISPLAY_NAME = "Twitter"
##############################################################################

class TwitterConnectionSettingsUI

  include PM::Dlg
  include AutoAccessor
  include CreateControlHelper

  def initialize(pm_api_bridge)
    @bridge = pm_api_bridge
  end

  def create_controls(parent_dlg)
    dlg = parent_dlg
    create_control(:setting_name_static,    Static,       dlg, :label=>"Your Accounts:")
    create_control(:setting_name_combo,     ComboBox,     dlg, :editable=>false, :sorted=>true, :persist=>false)
    create_control(:setting_delete_btn,     Button,       dlg, :label=>"Delete")
    create_control(:add_account_instructions,    Static,       dlg, :label=>"Note: If you have an active Twitter session in your browser, Twitter will authorize Photo Mechanic for the username associated with that session. Otherwise, Twitter will prompt you to login.")
    create_control(:add_account_button,     Button,       dlg, :label=>"Add Account")
  end

  def layout_controls(container)
    sh, eh = 20, 24
    c = container
    c.set_prev_right_pad(5).inset(10,10,-10,-10).mark_base
    c << @setting_name_static.layout(0, c.base, -1, sh)
    c.pad_down(0).mark_base
    c << @setting_name_combo.layout(0, c.base, -150, eh)
      c << @setting_delete_btn.layout(-140, c.base, -80, eh)
    c.pad_down(0).mark_base
    c.set_prev_right_pad(5).inset(10,30,-10,-10).mark_base
    c << add_account_instructions.layout(0, c.base, -1, 3*sh)
    c.pad_down(0).mark_base
    c.set_prev_right_pad(5).inset(10,30,-10,-10).mark_base
    c << @add_account_button.layout(0, c.base, -340, eh)
    c.pad_down(0).mark_base
  end
end

class TwitterConnectionSettings
  include PM::ConnectionSettingsTemplate

  DLG_SETTINGS_KEY = :connection_settings_dialog_01

  def self.template_display_name  # template name shown in dialog list box
    TEMPLATE_DISPLAY_NAME
  end

  def self.template_description  # shown in dialog box
    "Twitter Connection Settings"
  end

  def self.fetch_settings_data(serializer)
    dat = serializer.fetch(DLG_SETTINGS_KEY, :settings) || {}
    SettingsData.deserialize_settings_hash(dat)
  end

  def self.store_settings_data(serializer, settings)
    settings_dat = SettingsData.serialize_settings_hash(settings)
    serializer.store(DLG_SETTINGS_KEY, :settings, settings_dat)
  end

  def self.fetch_selected_settings_name(serializer)
    serializer.fetch(DLG_SETTINGS_KEY, :selected_item)  # might be nil
  end

  class SettingsData
    attr_accessor :auth_token, :auth_token_secret, :user_name

    def self.serialize_settings_hash(settings)
      out = {}
      settings.each_pair do |name, settings_values|
        if settings_values.is_a? Hash
          user_name = settings_values[:user_name]
          out[user_name] = [settings_values[:auth_token_secret], user_name, settings_values[:auth_token]]
        else
          # todo: make sure settings_values type is always the same in order to avoid this type checking
          user_name = if settings_values.user_name.is_a?(String)
                        settings_values.user_name
                      elsif settings_values.user_name.is_a?(Integer)
                        name
                      else
                        settings_values.user_name[0]
                      end
          out[user_name] = [settings_values.auth_token_secret, user_name, settings_values.auth_token]
        end
      end
      out
    end

    def self.deserialize_settings_hash(input)
      settings = {}
      input.each_pair do |key, dat|
        token_secret, user_name, token = dat
        settings[key] = SettingsData.new({
          :auth_token => token,
          :auth_token_secret => token_secret,
          :user_name => user_name
        })
      end
      settings
    end

    def initialize(args = {})
      @auth_token = args[:auth_token]
      @auth_token_secret = args[:auth_token_secret]
      @user_name = args[:user_name]
      self
    end

    def values
      [auth_token, auth_token_secret, user_name]
    end

    def appears_valid?
      !@auth_token.nil? && !@auth_token.empty? && !@auth_token_secret.nil? && !@auth_token_secret.empty?
    rescue
      false
    end
  end

  def initialize(pm_api_bridge)
    @bridge = pm_api_bridge
    @prev_selected_settings_name = nil
    @settings = {}
    @current_name = ''
  end

  def settings_selected_item
    serializer.fetch(DLG_SETTINGS_KEY, :selected_item)
  end

  def create_controls(parent_dlg)
    @ui = TwitterConnectionSettingsUI.new(@bridge)
    @ui.create_controls(parent_dlg)
    add_event_handlers
  end

  def add_event_handlers
    @ui.setting_name_combo.on_edit_change { handle_rename_selected }
    @ui.setting_name_combo.on_sel_change { handle_sel_change }
    @ui.add_account_button.on_click { handle_add_account }
    @ui.setting_delete_btn.on_click { handle_delete_button }
  end

  def layout_controls(container)
    @ui.layout_controls(container)
  end

  def destroy_controls
    @ui = nil
  end

  def save_state(serializer)
    return unless @ui
    # save_current_values_to_settings
    self.class.store_settings_data(serializer, @settings)
    serializer.store(DLG_SETTINGS_KEY, :selected_item, @current_name)
  end

  def restore_state(serializer)
    @settings = self.class.fetch_settings_data(serializer)
    load_combo_from_settings
    select_previously_selected_account(serializer)
    select_first_account_if_none_selected
    store_selected_account

    load_current_values_from_settings
  end

  def select_previously_selected_account(serializer)
    @prev_selected_settings_name = serializer.fetch(DLG_SETTINGS_KEY, :selected_item)
    if @prev_selected_settings_name
      @ui.setting_name_combo.set_selected_item(@prev_selected_settings_name)
    end
  end

  def select_first_account_if_none_selected
    if @ui.setting_name_combo.get_selected_item.empty?  &&  @ui.setting_name_combo.num_items > 0
      @ui.setting_name_combo.set_selected_item( @ui.setting_name_combo.get_item_at(0) )
    end
  end

  def store_selected_account
    @prev_selected_settings_name = @ui.setting_name_combo.get_selected_item
    @prev_selected_settings_name = nil if @prev_selected_settings_name.empty?
  end

  def periodic_timer_callback
  end

  protected

  def load_combo_from_settings
    @ui.setting_name_combo.reset_content( @settings.keys )
  end

  def save_current_values_to_settings(params={:name=>nil, :replace=>true})
    key = params[:name] || @current_name

    if key && key === String
      ensure_name_does_not_collide(key) unless params[:replace]

      @settings[key] ||= SettingsData.new({
        :auth_token => nil,
        :auth_token_secret => nil,
        :user_name => nil
      })

      key
    end
  end

  def current_account_name
    @ui.setting_name_combo.get_selected_item_text.to_s
  end

  def ensure_name_does_not_collide(current_name)
    if current_name.to_s.empty?
      return "" unless current_values_worth_saving?
      current_name = find_non_colliding_name("Untitled")
    else
      current_name = find_non_colliding_name(current_name)
    end
  end

  def load_current_values_from_settings
    cur_name = current_account_name.to_s
    data = @settings[cur_name]
  end

  def current_values_worth_saving?
    ! (current_account_name.empty? && @current_name.empty?)
  end

  def find_non_colliding_name(want_name)
    i = 1
    new_name = want_name
    while @ui.setting_name_combo.has_item? new_name
      i += 1
      new_name = "#{want_name} #{i}"
    end
    new_name
  end

  def rename_in_settings(old_name, new_name)
    data = @settings[old_name]
    @settings.delete old_name
    @settings[new_name] = data
  end

  def delete_in_settings(name)
    @settings.delete name
    @deleted = true
  end

  def handle_rename_selected
    had_prev = ! @prev_selected_settings_name.nil?
    cur_name = @ui.setting_name_combo.get_text.to_s
    if cur_name != @prev_selected_settings_name
      if had_prev
        @ui.setting_name_combo.remove_item @prev_selected_settings_name
      end

      return "" if cur_name.strip.empty? && !current_values_worth_saving?
      cur_name = "Untitled" if cur_name.strip.empty?
      new_name = find_non_colliding_name(cur_name)

      if had_prev
        rename_in_settings(@prev_selected_settings_name, new_name)
      else
        saved_name = save_current_values_to_settings(:name=>new_name, :replace=>true)
        return "" unless !saved_name.empty?
      end
      @ui.setting_name_combo.add_item new_name
      @prev_selected_settings_name = new_name
      cur_name = new_name
    end
    cur_name
  end

  def add_account_to_dropdown(name = nil)
    save_current_values_to_settings(:name => name.to_s, :replace=>true)
    @ui.setting_name_combo.add_item(name.to_s)
  end

  def handle_sel_change
    # NOTE: We rely fully on the prev. selected name here, because the
    # current selected name has already changed.
    if @prev_selected_settings_name
      save_current_values_to_settings(:name=>@prev_selected_settings_name, :replace=>true)
    end
    load_current_values_from_settings
    @prev_selected_settings_name = current_account_name
  end

  def clear_settings
    @ui.setting_name_combo.set_text ""
  end

  def client
    @client ||= TwitterClient.new(@bridge)
  end

  def handle_add_account
    save_account_callback = lambda do |client|
      if client.authenticated?
        @current_name = key = client.user_name

        @settings[key]  = SettingsData.new({
          :auth_token => client.access_token,
          :auth_token_secret => client.access_token_secret,
          :user_name => client.user_name
        })

        add_account_to_dropdown(key)
      end
    end

    client.launch_pincode_authorization(save_account_callback)
    @prev_selected_settings_name = nil
  end

  def handle_delete_button
    cur_name = current_account_name
    @ui.setting_name_combo.remove_item(cur_name) if @ui.setting_name_combo.has_item? cur_name
    delete_in_settings(cur_name)
    @prev_selected_settings_name = nil
    if @ui.setting_name_combo.num_items > 0
      @ui.setting_name_combo.set_selected_item( @ui.setting_name_combo.get_item_at(0) )
      handle_sel_change
    else
      clear_settings
    end
  end
end

class TwitterFileUploaderUI

  include PM::Dlg
  include AutoAccessor
  include CreateControlHelper
  include ImageProcessingControlsCreation
  include ImageProcessingControlsLayout
  include OperationsControlsCreation
  include OperationsControlsLayout

  SOURCE_RAW_LABEL = "Use the RAW"
  SOURCE_JPEG_LABEL = "Use the JPEG"

  DEST_EXISTS_UPLOAD_ANYWAY_LABEL = "Upload file anyway (files of same name can safely coexist)"
  DEST_EXISTS_RENAME_LABEL = "Rename file before uploading"
  DEST_EXISTS_SKIP_LABEL = "Skip file (do not upload)"

  def initialize(pm_api_bridge)
    @bridge = pm_api_bridge
  end

  def operations_enabled?
    false
  end

  def create_controls(parent_dlg)
    dlg = parent_dlg

    create_control(:dest_account_group_box,     GroupBox,       dlg, :label=>"Destination Twitter Account:")
    create_control(:dest_account_static,        Static,         dlg, :label=>"Account:", :align=>"right")
    create_control(:dest_account_combo,         ComboBox,       dlg, :sorted=>true, :persist=>false)
    create_control(:handle_add_account,   Button,         dlg, :label=>"Authorize...")
    create_control(:tweet_static, Static,       dlg, :label=> "Compose Tweet:", :align => 'right')
    create_control(:tweet_edit, EditControl,       parent_dlg, :value=> "", :multiline=>true, :persist=> false, :align => 'right')
    create_control(:tweet_length_static, Static,       dlg, :label=> "126", :align => 'left')

    create_control(:transmit_group_box,         GroupBox,       dlg, :label=>"Transmit:")
    create_control(:send_original_radio,        RadioButton,    dlg, :label=>"Original Photos", :checked=>true)
    create_control(:send_jpeg_radio,            RadioButton,    dlg, :label=>"Saved as JPEG")
    RadioButton.set_exclusion_group(@send_original_radio, @send_jpeg_radio)
    create_control(:send_desc_edit,             EditControl,    dlg, :value=>"Note: Twitter's supported image formats are PNG, JPG and GIF. Twitter removes all EXIF and IPTC data from uploaded images. If you'd like to retain credit, we recommend considering a watermark when sharing images on social media.", :multiline=>true, :readonly=>true, :persist=>false)
    create_jpeg_controls(dlg)
    create_image_processing_controls(dlg)
  end

  STATIC_TEXT_HEIGHT = 20
  EDIT_FIELD_HEIGHT = 24
  COLOR_BUTTON_HEIGHT = 24
  RIGHT_PAD = 5

  def layout_controls(container)
    sh = STATIC_TEXT_HEIGHT
    eh = EDIT_FIELD_HEIGHT
    ch = COLOR_BUTTON_HEIGHT
    rp = RIGHT_PAD
    w1 = 400

    container.inset(15, 5, -15, -5)

    container.layout_with_contents(@dest_account_group_box, 0, 0, -1, -1) do |c|
      c.set_prev_right_pad(rp).inset(10,25,-10,-5).mark_base

      c << @dest_account_static.layout(0, c.base+3, 100, sh)
      c << @dest_account_combo.layout(c.prev_right, c.base, 130, eh)
      # c << @authorize_button.layout(c.prev_right+5, c.base, 120, eh)

      c.pad_down(0).mark_base

      c << @tweet_static.layout(0, c.base + 8, 100, sh)
      c << @tweet_edit.layout(c.prev_right, c.base + 8, w1, eh*2)
      c << @tweet_length_static.layout(c.prev_right + 3, c.base + eh*2 -sh/2, 70, sh)

      c.pad_down(5).mark_base
      c.mark_base.size_to_base
    end


    container.pad_down(5).mark_base

    container.layout_with_contents(@transmit_group_box, 0, container.base, "100%-3", -1) do |xmit_container|
      c = xmit_container
      c.set_prev_right_pad(rp).inset(10,25,-10,-5).mark_base

      c << @send_original_radio.layout(0, c.base, 120, eh)
      save_right, save_base = c.prev_right, c.base
      c.pad_down(5).mark_base
      c << @send_jpeg_radio.layout(0, c.base, 120, eh)
        c << @send_desc_edit.layout(save_right+5, save_base, -1, 76)
      c.pad_down(5).mark_base

      layout_jpeg_controls(c, eh, sh)

      c.layout_with_contents(@imgproc_group_box, 0, c.base, -1, -1) do |c|
        c.set_prev_right_pad(rp).inset(10,25,-10,-5).mark_base

        w1, w2 = 70, 182
        w1w = (w2 - w1)
        layout_image_processing_controls(c, eh, sh, w1, w2, w1w)
      end
      c = xmit_container

      c.pad_down(5).mark_base
      c.mark_base.size_to_base
    end

    container.pad_down(20).mark_base
  end

  def have_source_raw_jpeg_controls?
    defined?(@source_raw_jpeg_static) && defined?(@source_raw_jpeg_combo)
  end

  def raw_jpeg_render_source
    src = "JPEG"
    if have_source_raw_jpeg_controls?
      src = "RAW" if @source_raw_jpeg_combo.get_selected_item == SOURCE_RAW_LABEL
    end
    src
  end
end

class TwitterBackgroundDataFetchWorker
  def initialize(bridge, dlg)
    @bridge = bridge
    @dlg = dlg
    @client = TwitterClient.new(@bridge)
  end

  def account
    @dlg.account
  end

  def configuration
  end

  def do_task
    validate_number_of_images

    return unless @dlg.account_parameters_dirty

    @dlg.reset_active_account
    check_status if @dlg.account_valid?
    @dlg.adjust_tweet_length_indicator
    @dlg.account_parameters_dirty = false

  rescue => e
    @dlg.set_status_text "Error communicating with twitter: #{e}"
  end

  def validate_number_of_images
    if @dlg.num_files > 1
      @dlg.set_status_text("More than one photo selected!")
      @dlg.disable_ui
    end
  end

  def check_status
    @dlg.set_status_text("Checking connection status...")
    status = @client.get_configuration

    if status.class === Hash && status['errors']
      @dlg.set_status_text(status['errors'].first['message'])
    else
      # @dlg.disable_authorize_button
      @dlg.set_status_text("You are logged in and ready to tweet.")
    end
  end
end

class TwitterFileUploader
  include PM::FileUploaderTemplate
  include ImageProcessingControlsLogic
  include OperationsControlsLogic
  include RenamingControlsLogic
  include JpegSizeEstimationLogic
  include UpdateComboLogic
  include FormatBytesizeLogic
  include PreflightWaitAccountParametersLogic

  attr_accessor :account_parameters_dirty, :authenticated_protocol
  attr_reader :num_files, :ui

  DLG_SETTINGS_KEY = :upload_dialog

  def self.template_display_name
    TEMPLATE_DISPLAY_NAME
  end

  def self.template_description
    "Upload an image to Twitter"
  end

  def self.conn_settings_class
    TwitterConnectionSettings
  end

  def initialize(pm_api_bridge, num_files, dlg_status_bridge, conn_settings_serializer)
    @bridge = pm_api_bridge
    @num_files = num_files
    @dlg_status_bridge = dlg_status_bridge
    @conn_settings_ser = conn_settings_serializer
    @last_status_txt = nil
    @account_parameters_dirty = false
    @data_fetch_worker = nil
  end

  def upload_files(global_spec, progress_dialog)
    raise "upload_files called with no @ui instantiated" unless @ui
    acct = current_account_settings
    raise "Failed to load settings for current account. Please click the Connections button." unless acct
    spec = build_upload_spec(acct, @ui)
    @bridge.kickoff_template_upload(spec, TwitterUploadProtocol)
  end

  def preflight_settings(global_spec)
    raise "preflight_settings called with no @ui instantiated" unless @ui

    acct = current_account_settings
    raise "Failed to load settings for current account. Please click the Connections button." unless acct
    raise "Some account settings appear invalid or missing. Please click the Connections button." unless acct.appears_valid?

    preflight_jpeg_controls
    preflight_wait_account_parameters_or_timeout

    build_upload_spec(acct, @ui)
  end

  def create_controls(parent_dlg)
    @ui = TwitterFileUploaderUI.new(@bridge)
    @ui.create_controls(parent_dlg)

    # @ui.authorize_button.on_click { handle_authorize_button }
    @ui.send_original_radio.on_click { adjust_controls }
    @ui.send_jpeg_radio.on_click { adjust_controls }

    @ui.dest_account_combo.on_sel_change {account_parameters_changed}
    @ui.tweet_edit.on_edit_change { adjust_tweet_length_indicator }

    add_jpeg_controls_event_hooks
    add_image_processing_controls_event_hooks
    set_seqn_static_to_current_seqn
    add_default_tweet_content

    @last_status_txt = nil

    create_data_fetch_worker
  end

  def adjust_tweet_length_indicator
    @ui.tweet_edit.enable(false)

    text = @ui.tweet_edit.get_text
    length = text.length
    link_char_count = (config && !config.is_a?(Hash)) ? config.link_char_count || 0 : 0
    tweet_length = 140
    remaining = tweet_length - (length + link_char_count)

    @ui.tweet_edit.set_text(text[0..remaining]) if remaining < 0

    text = tweet_body
    length = text.length
    tweet_length = 140
    remaining = tweet_length - (length + link_char_count)

    @ui.tweet_length_static.set_text(remaining.to_s)
    @ui.tweet_edit.enable(true)
  end

  def tweet_body
    @ui.tweet_edit.get_text
  end

  def add_default_tweet_content
    @ui.tweet_edit.set_text("")
  end

  # def handle_authorize_button
  #   authenticated_protocol.launch_pincode_authorization
  # end

  def enable_authorize_button
    # @ui.authorize_button.enable(true)
  end

  def disable_authorize_button
    # @ui.authorize_button.enable(false)
  end

  def layout_controls(container)
    @ui.layout_controls(container)
  end

  def destroy_controls
    destroy_data_fetch_worker
    @ui = nil
  end

  def reset_active_account
    account_parameters_changed
  end

  def selected_account
    @ui.dest_account_combo.get_selected_item_text
  end

  def save_state(serializer)
    return unless @ui
    serializer.store(DLG_SETTINGS_KEY, :selected_account, @ui.dest_account_combo.get_selected_item)
  end

  def restore_state(serializer)
    reset_account_combo_from_settings
    select_previous_account(serializer)
    select_first_available_if_present
    account_parameters_changed
    adjust_controls
  end

  def reset_account_combo_from_settings
    data = fetch_conn_settings_data
    @ui.dest_account_combo.reset_content( data.keys )
  end

  def select_previous_account(serializer)
    prev_selected_account = serializer.fetch(DLG_SETTINGS_KEY, :selected_account)
    @ui.dest_account_combo.set_selected_item(prev_selected_account) if prev_selected_account
  end

  def select_first_available_if_present
    if @ui.dest_account_combo.get_selected_item.empty?  &&  @ui.dest_account_combo.num_items > 0
      @ui.dest_account_combo.set_selected_item( @ui.dest_account_combo.get_item_at(0) )
    end
  end


  def periodic_timer_callback
    return unless @ui
    @data_fetch_worker.exec_messages
    handle_jpeg_size_estimation
  end

  def set_status_text(txt)
    if txt != @last_status_txt
      @dlg_status_bridge.set_text(txt)
      @last_status_txt = txt
    end
  end

  def update_account_combo_list
    data = fetch_conn_settings_data
    @ui.dest_account_combo.reset_content( data.keys )
  end

  def select_active_account
    selected_settings_name = TwitterConnectionSettings.fetch_selected_settings_name(@conn_settings_ser)
    if selected_settings_name
      @ui.dest_account_combo.set_selected_item( selected_settings_name )
    end

    # if selection didn't take, and we have items in the list, just pick the 1st one
    if @ui.dest_account_combo.get_selected_item.empty?  &&  @ui.dest_account_combo.num_items > 0
      @ui.dest_account_combo.set_selected_item( @ui.dest_account_combo.get_item_at(0) )
    end
  end

  # Called by the framework after user has closed the Connection Settings dialog.
  def connection_settings_edited(conn_settings_serializer)
    @conn_settings_ser = conn_settings_serializer

    update_account_combo_list
    select_active_account
    account_parameters_changed
  end

  def authenticated_protocol
    unless @authenticated_protocol
      prot = nil
      begin

        prot = TwitterUploadProtocol.new(@bridge, {
          :connection_settings_serializer => @conn_settings_ser,
          :dialog => self
        })

        prot.authenticate_from_settings({
          :token => account.auth_token,
          :token_secret => account.auth_token_secret
        }) if tokens_present?

      rescue Exception => ex
        display_message_box "Unable to login to Twitter server. Please click the Connections button.\nError: #{ex.message}"
        (prot.close if prot) rescue nil
        raise
      end
    end

    @authenticated_protocol ||= prot
  end

  def config
    authenticated_protocol.config
  end

  # account from settings data
  def account
    @account = current_account_settings
  end

  def account_valid?
    (account_empty? || account_invalid?) ? false : true
  end

  def toggle_authorize_button
    # enable  = if (account_empty? || account_valid?)
    #   false
    # else
    #   true
    # end
    # @ui.authorize_button.enable(enable)
  end

  def disable_ui
    @ui.tweet_edit.enable(false)
    # @ui.send_button.enable(false)
  end

  def imglink_button_spec
    { :filename => "logo.tif", :bgcolor => "ffffff" }
  end

  def imglink_url
    "https://www.twitter.com/"
  end

  protected

  def create_data_fetch_worker
    qfac = lambda { @bridge.create_queue }
    @data_fetch_worker = BackgroundDataFetchWorkerManager.new(TwitterBackgroundDataFetchWorker, qfac, [@bridge, self])
  end

  def destroy_data_fetch_worker
    if @data_fetch_worker
      @data_fetch_worker.terminate
      @data_fetch_worker = nil
    end
  end

  def display_message_box(text)
    Dlg::MessageBox.ok(text, Dlg::MessageBox::MB_ICONEXCLAMATION)
  end

  def adjust_controls
    adjust_image_processing_controls
    toggle_authorize_button
  end

  def build_upload_spec(acct, ui)
    spec = AutoStruct.new

    # string displayed in upload progress dialog title bar:
    spec.upload_display_name  = "twitter.com:#{acct.user_name}"
    # string used in logfile name, should have NO spaces or funky characters:
    spec.log_upload_type      = TEMPLATE_DISPLAY_NAME.tr('^A-Za-z0-9_-','')
    # account string displayed in upload log entries:
    spec.log_upload_acct      = spec.upload_display_name

    spec.token = authenticated_protocol.access_token
    spec.token_secret = authenticated_protocol.access_token_secret
    spec.tweet_body = tweet_body

    # FIXME: we're limiting concurrent uploads to 1 because
    #        end of queue notification happens per uploader thread
    #        and we can still be uploading, causing
    #        partially transmitted files get prematurely
    #        harvested on the server side
    spec.max_concurrent_uploads = 1

    spec.num_files = @num_files

    # NOTE: upload_queue_key should be unique for a given protocol,
    #       and a given upload "account".
    #       Rule of thumb: If file A requires a different
    #       login than file B, they should have different
    #       queue keys.
    #       IMPORTANT: Since Twitter end-of-queue upload job
    #       applies to a given galery, we require that uploads to
    #       differing galleries be separated into their own queues.
    #       Thus, we make gallery part of the queue key.
    spec.upload_queue_key = [
      "Twitter"
    ].join("\t")

    spec.upload_processing_type = ui.send_original_radio.checked? ? "originals_jpeg_only" : "save_as_jpeg"
    spec.send_incompatible_originals_as = "JPEG"
    spec.send_wav_files = false

    spec.apply_stationery_pad = false
    spec.preserve_exif = false
    spec.save_transmitted_photos = false
    spec.do_rename = false
    spec.save_photos_subdir_type = 'specific'

    build_jpeg_spec(spec, ui)
    build_image_processing_spec(spec, ui)

    spec
  end

  def fetch_conn_settings_data
    TwitterConnectionSettings.fetch_settings_data(@conn_settings_ser)
  end

  def current_account_settings
    acct_name = @ui.dest_account_combo.get_selected_item
    data = fetch_conn_settings_data
    settings = data ? data[acct_name] : nil
  end

  def tokens_present?
    account && account.appears_valid?
  end

  def account_empty?
    if account.nil?
      notify_account_missing
      return true
    else
      return false
    end
  end

  def account_invalid?
    if account && account.appears_valid?
      return false
    else
      notify_account_invalid
      return true
    end
  end

  def notify_account_missing
    set_status_text("Please select an account, or create one with the Connections button.")
  end

  def notify_account_invalid
    set_status_text("You need to authorize your account.")
  end

  def account_parameters_changed
    @account = nil
    @account_parameters_dirty = true
  end
end

class TwitterPincodeVerifierDialog < Dlg::DynModalChildDialog

  include PM::Dlg
  include CreateControlHelper

  attr_accessor :access_token, :access_token_secret, :user_name

  def initialize(api_bridge, client, dialog_end_callback)
    @bridge = api_bridge
    @access_token = nil
    @access_token_secret = nil
    @user_name = nil
    @client = client
    @dialog_end_callback = dialog_end_callback
    super()
  end

  def init_dialog
    dlg = self
    dlg.set_window_position_key("TwitterPincodeVerifierDialogT")
    dlg.set_window_position(50, 200, 300, 160)
    title = "Verify Pincode"
    dlg.set_window_title(title)

    parent_dlg = dlg
    create_control(:pincode_static,       Static,         parent_dlg, :label=>"Enter the pincode:", :align=>"left")
    create_control(:pincode_edit,         EditControl,    parent_dlg, :value=>"", :persist=>false)

    create_control(:submit_button,            Button,         parent_dlg, :label=>"Submit")
    create_control(:cancel_button,            Button,         parent_dlg, :label=>"Cancel")


    @submit_button.on_click { get_access_token }
    @cancel_button.on_click { closebox_clicked }

    layout_controls
    instantiate_controls
    show(true)
  end

  def destroy_dialog!
    @dialog_end_callback.call(@access_token, @access_token_secret, @user_name) if @dialog_end_callback
    super
  end

  def layout_controls
    sh = 20
    eh = 24
    bh = 28
    dlg = self
    client_width, client_height = dlg.get_clientrect_size
    c = LayoutContainer.new(0, 0, client_width, client_height)
    c.inset(16, 10, -16, -10)

    w1 = 250
    c << @pincode_static.layout(0, c.base, w1, sh)
    c.pad_down(0).mark_base
    c << @pincode_edit.layout(0, c.base, w1, eh)
    c.pad_down(5).mark_base

    bw = 80
    c << @submit_button.layout(-(bw*2+10), -bh, bw, bh)
    c << @cancel_button.layout(-bw, -bh, bw, bh)
  end

  protected

  def pincode_value
    @pincode_edit.get_text.strip
  end

  def pincode_value_empty?
    pincode_value.empty?
  end

  def notify_pincode_value_blank
    Dlg::MessageBox.ok("Please enter a non-blank pincode.", Dlg::MessageBox::MB_ICONEXCLAMATION)
  end

  def get_access_token
    notify_pincode_value_blank and return if pincode_value_empty?

    begin
      oauth_verifier = pincode_value
      result = @client.get_access_token(oauth_verifier)
      store_access_settings(result)
    rescue StandardError => ex
      Dlg::MessageBox.ok("Failed to authorize with Twitter. Error: #{ex.message}", Dlg::MessageBox::MB_ICONEXCLAMATION)
    ensure
      end_dialog(IDOK)
    end
  end

  def store_access_settings(result)
    @access_token = result[:access_token]
    @access_token_secret = result [:access_token_secret]
    @user_name = result[:user_name]
  end
end

class TwitterClient
  BASE_URL = "https://api.twitter.com/"
  API_KEY = 'n4ymCL7XJjI6d3FnfvRNwUv1X'
  API_SECRET = '9lEB25A6LZGBKK5MY7ZW494jOC0bW0cpxmOjxW4ZTlutLY5YTg'

  attr_accessor :access_token, :access_token_secret, :user_name
  attr_accessor :config

  def initialize(bridge, options = {})
    @bridge = bridge
    @authenticated = false
  end

  def reset!
    @access_token = nil
    @access_token_secret = nil
    @user_name = nil
  end

  def to_h
    {
        :access_token => @access_token,
        :access_token_secret => @access_token_secret,
        :user_name => @user_name
    }
  end

  def launch_pincode_authorization(callback)
    reset!
    fetch_request_token
    launch_pincode_authorization_in_browser
    open_pincode_entry_dialog(callback)
  end

  def fetch_request_token
    response = post('oauth/request_token')

    result = CGI::parse(response.body)

    @access_token = result['oauth_token']
    @access_token_secret = result['oauth_token_secret']
    @access_token
  end

  def launch_pincode_authorization_in_browser
    fetch_request_token unless @access_token
    pincode_url = "https://api.twitter.com/oauth/authorize?oauth_token=#{@access_token}"
    @bridge.launch_url(pincode_url)
  end

  def open_pincode_entry_dialog(callback)
    callback_a = lambda do |token, token_secret, user_name|
      store_settings_data(token, token_secret, user_name)
      callback.call(self)
      # update_ui
    end
    cdlg = TwitterPincodeVerifierDialog.new(@bridge, self, callback_a)
    cdlg.instantiate!
    cdlg.request_deferred_modal
  end

  def get_access_token(verifier)
    @verifier = verifier
    response = post('oauth/access_token')
    result = CGI::parse(response.body)

    @access_token = result['oauth_token']
    @access_token_secret = result['oauth_token_secret']
    @user_name = result['screen_name']

    to_h
  end

  def authenticate_from_settings(settings = {})
    @access_token = settings[:token]
    @access_token_secret = settings[:token_secret]
  end

  def update_ui
    @dialog.reset_active_account
  end

  def authenticated?
    @authenticated
  end

  def store_settings_data(token, token_secret, user_name)
    @access_token = token
    @access_token_secret = token_secret
    @user_name = user_name
    @authenticated = true
  end

  def get_rate_status
    response = get('1.1/application/rate_limit_status.json')
    response_body = JSON.parse(response.body)
  end

  def get_configuration
    unless @config
      response = get('1.1/help/configuration.json')
      response_body = JSON.parse(response.body)
      config = TwitterConfiguration.from_response(response_body)


      @config ||= config
    end
  end

  def verify_credentials
    response = get('1.1/account/verify_credentials.json')
    JSON.parse(response.body)
  end

  def post_tweet(data, headers)
    response = post('1.1/statuses/update_with_media.json', data, headers)
  end

  protected

  def request_headers(method, url, params = {}, signature_params = params)
    {'Authorization' => auth_header(method, url, params, signature_params)}
  end

  def auth_header(method, url, params = {}, signature_params = params)
    oauth_auth_header(method, url, signature_params).to_s
  end

  def oauth_auth_header(method, uri, params = {})
    uri = URI.parse(uri)
    SimpleOAuth::Header.new(method, uri, params, credentials)
  end

  def credentials
    {
        :consumer_key    => API_KEY,
        :consumer_secret => API_SECRET,
        :token           => @access_token,
        :token_secret    => @access_token_secret,
        :verifier => @verifier,
        :callback => 'oob'
    }
  end

  # todo: handle timeout
  def ensure_open_http(host, port)
    unless @http
      @http = @bridge.open_http_connection(host, port)
      @http.use_ssl = true
      @http.open_timeout = 60
      @http.read_timeout = 180
    end
  end

  def close_http
    if @http
      @http.finish rescue nil
      @http = nil
    end
  end

  def get(path, params = {})
    headers = request_headers(:get, BASE_URL + path, params, {})
    request(:get, path, params, headers)
  end

  def post(path, params = {}, upload_headers = {})
    uri = BASE_URL + path
    headers = request_headers(:post, uri, params, {})
    headers.merge!(upload_headers)
    request(:post, path, params, headers)
  end

  def request(method, path, params = {}, headers = {})
    url = BASE_URL + path
    uri = URI.parse(url)
    ensure_open_http(uri.host, uri.port)

    if method == :get
      @http.send(method.to_sym, uri.request_uri, headers)
    else
      @http.send(method.to_sym, uri.request_uri, params, headers)
    end
  end

  def require_server_success_response(resp)
    raise(RuntimeError, resp.inspect) unless resp.code == "200"
  end
end

class TwitterUploadProtocol

  BASE_URL = "https://api.twitter.com/"
  API_KEY = 'n4ymCL7XJjI6d3FnfvRNwUv1X'
  API_SECRET = '9lEB25A6LZGBKK5MY7ZW494jOC0bW0cpxmOjxW4ZTlutLY5YTg'

  attr_reader :access_token, :access_token_secret, :user_name
  attr_accessor :config

  def initialize(pm_api_bridge, options = {:connection_settings_serializer => nil, :dialog => nil})
    @bridge = pm_api_bridge
    @shared = @bridge.shared_data
    @http = nil
    @access_token = nil
    @access_token_secret = nil
    @dialog = options[:dialog]
    @connection_settings_serializer = options[:connection_settings_serializer]
    @config = nil
    mute_transfer_status
    close
  end

  def mute_transfer_status
    # we may make multiple requests while uploading a file, and
    # don't want the progress bar to jump around until we get
    # to the actual upload
    @mute_transfer_status = true
  end

  def close
    # close_http
  end

  def reset!
    @access_token = nil
    @access_token_secret = nil
  end

  def image_upload(local_filepath, remote_filename, is_retry, spec)
    @bridge.set_status_message "Uploading via secure connection..."

    @access_token = spec.token
    @access_token_secret = spec.token_secret
    tweet_body = spec.tweet_body

    upload(local_filepath, remote_filename, tweet_body)

    @shared.mutex.synchronize {
      dat = (@shared[spec.upload_queue_key] ||= {})
      dat[:pending_uploadjob] ||= 0
      dat[:pending_uploadjob] += 1
    }

    remote_filename
  end

  def transfer_queue_empty(spec)
    job_url = nil
    @shared.mutex.synchronize {
      dat = (@shared[spec.upload_queue_key] ||= {})

      if dat[:pending_uploadjob].to_i > 0
        job_url = dat[:uploadjob_url]
        dat[:pending_uploadjob] = 0
      end
    }

    if job_url
      uploadjob(job_url)
    end
  end

  def reset_transfer_status
    (h = @http) and h.reset_transfer_status
  end

  # return [bytes_to_write, bytes_written]
  def poll_transfer_status
    if (h = @http)  &&  ! @mute_transfer_status
      [h.bytes_to_write, h.bytes_written]
    else
      [0, 0]
    end
  end

  def abort_transfer
    (h = @http) and h.abort_transfer
  end

  def upload(fname, remote_filename, tweet_body)
    fcontents = @bridge.read_file_for_upload(fname)

    mime = MimeMultipart.new
    mime.add_field("status", tweet_body)
    mime.add_field("source", '<a href="http://store.camerabits.com">Photo Mechanic 5</a>')
    mime.add_field("include_entities", "true")
    mime.add_image("media[]", remote_filename, fcontents, "application/octet-stream")

    data, headers = mime.generate_data_and_headers

    begin
      @mute_transfer_status = false
      verify_credentials
      resp = post_tweet(data, headers)
      require_server_success_response(resp)
    ensure
      @mute_transfer_status = true
    end
  end

  def generate_photo_id(filename)
    Digest::SHA1.hexdigest "#{Time.now.to_s}-#{filename}"
  end

  def uploadjob(order)
    xmlquery = "<uploadjob>\n"
    xmlquery += "<order uri=\"#{order}\"\/>\n"
    xmlquery += "<settings />\n"
    xmlquery += "</uploadjob>\n"
    headers = { 'Content-Type' => 'application/xml', 'Cookie' => @api_key}
    resp = post("uploadjobs", xmlquery, headers)
    sleep 5.0  # FIXME: KLUDGE: grr... we wouldn't want to return and find a new file added to the queue and immediately upload it while the job is still processing... not sure how to wait the correct length of time
  end

  def authenticate_from_settings(settings = {})
    @access_token = settings[:token]
    @access_token_secret = settings[:token_secret]
  end

  def verify_credentials
    response = get('1.1/account/verify_credentials.json')
    JSON.parse(response.body)
  end
  #
  def post_tweet(data, headers)
    response = post('1.1/statuses/update_with_media.json', data, headers)
  end

  protected

  def request_headers(method, url, params = {}, signature_params = params)
   {'Authorization' => auth_header(method, url, params, signature_params)}
  end

  def auth_header(method, url, params = {}, signature_params = params)
    oauth_auth_header(method, url, signature_params).to_s
  end

  def oauth_auth_header(method, uri, params = {})
    uri = URI.parse(uri)
    SimpleOAuth::Header.new(method, uri, params, credentials)
  end

  def credentials
    {
      :consumer_key    => API_KEY,
      :consumer_secret => API_SECRET,
      :token           => @access_token,
      :token_secret    => @access_token_secret,
      :verifier => @verifier,
      :callback => 'oob'
    }
  end

  # todo: handle timeout
  def ensure_open_http(host, port)
    unless @http
      @http = @bridge.open_http_connection(host, port)
      @http.use_ssl = true
      @http.open_timeout = 60
      @http.read_timeout = 180
    end
  end

  def close_http
    if @http
      @http.finish rescue nil
      @http = nil
    end
  end

  def get(path, params = {})
    headers = request_headers(:get, BASE_URL + path, params, {})
    request(:get, path, params, headers)
  end

  def post(path, params = {}, upload_headers = {})
    uri = BASE_URL + path
    headers = request_headers(:post, uri, params, {})
    headers.merge!(upload_headers)
    request(:post, path, params, headers)
  end

  def request(method, path, params = {}, headers = {})
    url = BASE_URL + path
    uri = URI.parse(url)
    ensure_open_http(uri.host, uri.port)

    if method == :get
      @http.send(method.to_sym, uri.request_uri, headers)
    else
      @http.send(method.to_sym, uri.request_uri, params, headers)
    end
  end

  def require_server_success_response(resp)
    raise(RuntimeError, resp.inspect) unless resp.code == "200"
  end
end

class TwitterConfiguration
  attr_accessor :image_size_limit, :link_char_count, :max_images

  def self.from_response(response_body)
    if response_body['errors']
      response_body
    else
      image_size_limit = response_body['photo_size_limit']
      link_char_count = response_body['short_url_length_https']
      max_images = response_body['max_media_per_upload']

      new({
        :image_size_limit => image_size_limit,
        :link_char_count => link_char_count,
        :max_images => max_images
      })
    end
  end

  def initialize(args = {})
    @image_size_limit ||= args[:image_size_limit]
    @link_char_count ||= args[:link_char_count]
    @max_images ||= args[:max_images]
  end
end
