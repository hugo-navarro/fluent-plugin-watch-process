require 'time'
require 'csv' if Fluent.windows?
require "fluent/plugin/input"
require 'fluent/mixin/rewrite_tag_name'
require 'fluent/mixin/type_converter'

module Fluent::Plugin
  class WatchProcessInput < Fluent::Plugin::Input
    Fluent::Plugin.register_input('watch_process', self)

    helpers :timer
    
    # This default keys, for windows, will be overwritten by the WindowsWatcher class.
    # Notice that in linux and mac, the data will be gathered straight form the list of processes. Only for windows we have a different approach to associate the services with the processes.
    DEFAULT_KEYS = %w(start_time user pid parent_pid cpu_time cpu_percent memory_percent mem_rss mem_size state proc_name command)
    DEFAULT_TYPES = %w(
      pid:integer
      parent_pid:integer
      cpu_percent:float
      memory_percent:float
      mem_rss:integer
      mem_size:integer
    ).join(",")

    config_param :tag, :string
    config_param :command, :string, :default => nil
    config_param :keys, :array, :default => nil
    config_param :interval, :time, :default => '5s'
    config_param :lookup_user, :array, :default => nil
    config_param :hostname_command, :string, :default => 'hostname'
    config_param :powershell_command, :enum, list: [:powershell, :pwsh], :default => :powershell

    include Fluent::HandleTagNameMixin
    include Fluent::Mixin::RewriteTagName
    include Fluent::Mixin::TypeConverter

    def initialize
      super
    end

    def configure(conf)
      super

      @windows_watcher = WindowsWatcher.new(@keys, @command, @powershell_command) if Fluent.windows?
      @keys ||= Fluent.windows? ? @windows_watcher.keys : DEFAULT_KEYS
      @command ||= get_ps_command
      apply_default_types
      log.info "watch_process: polling start. :tag=>#{@tag} :lookup_user=>#{@lookup_user} :interval=>#{@interval} :command=>#{@command}"
    end

    def start
      super
      timer_execute(:in_watch_process, @interval, &method(:on_timer))
    end

    def shutdown
      super
    end

    def apply_default_types
      return unless @types.nil?
      @types = Fluent.windows? ? @windows_watcher.default_types : DEFAULT_TYPES
      @type_converters = parse_types_parameter unless @types.nil?
    end

    def on_timer
      io = IO.popen(@command, 'r')
      begin
        io.gets
        while result = io.gets
          if result.strip.start_with?("+ CategoryInfo", "ParserError")
            log.error "watch_process: PowerShell command error - #{result}"
            next
          end

          if Fluent.windows?
            data = @windows_watcher.parse_line(result)
          else
            data = Hash[@keys.zip(result.strip.split(/\s+/, @keys.size))]
          end
          emit_tag = tag.dup
          filter_record(emit_tag, Fluent::Engine.now, data)
          router.emit(emit_tag, Fluent::Engine.now, data)
        end
      ensure
        io.close
      end
    rescue StandardError => e
      log.error "watch_process: error has occured. #{e.message}"
    end

    def match_look_up_user?(data)
      return true if @lookup_user.nil?

      @lookup_user.include?(data['user'])
    end

    def get_ps_command
      if mac?
        "LANG=en_US.UTF-8 && ps -ewwo lstart,user,pid,ppid,time,%cpu,%mem,rss,vsz,state,comm,command"
      elsif Fluent.windows?
        @windows_watcher.command
      else
        "LANG=en_US.UTF-8 && ps -ewwo lstart,user:20,pid,ppid,time,%cpu,%mem,rss,sz,s,comm,cmd"
      end
    end

    def mac?
      (/darwin/ =~ RUBY_PLATFORM) != nil
    end

    class WindowsWatcher
      # Keys are from the "System.Diagnostics.Process" object properties that can be taken by the "Get-Process" command.
      # You can check the all properties by the "(Get-Process)[0] | Get-Member" command.
      DEFAULT_KEYS = %w(ServiceName DisplayName Status StartType ProcessID ExecutablePath CommandLine CreationDate CPUTime MemoryUsage)

      DEFAULT_TYPES = %w(
        ProcessID:integer
        CPUTime:float
        MemoryUsage:float
      ).join(",")

      attr_reader :keys
      attr_reader :command

      def initialize(keys, command, powershell_command)
        @keys = keys || DEFAULT_KEYS
        @powershell_command = powershell_command
        @command = command || default_command
      end

      def default_types
        DEFAULT_TYPES
      end

      def parse_line(line)
        values = CSV.parse_line(line.chomp.strip)
        return {} if values.nil?

        data = Hash[@keys.zip(values)]

        # unless data["CreationDate"].nil?
        #   creation_date = Time.parse(data['CreationDate'])
        #   data['ElapsedTime'] = (Time.now - creation_date).to_i
        #   data["CreationDate"] = creation_date.to_s
        # end

        data
      end

      def default_command
        command = [
          command_ps,
          pipe_filtering_service,
          pipe_select_process,
          pipe_filter_process,
          pipe_select_process_details,
          pipe_select_process_null,
          pipe_formatting_output
        ].join
        "#{@powershell_command} -command \"#{command}\""
      end

      def command_ps
        "Get-Service | Where-Object { $_.Status -eq 'Running' }"
      end

      # We are trying to get the services that are running and the processes that are associated with them.
      def pipe_filtering_service
        " | ForEach-Object { $service = $_; $processes = Get-Process -Name $service.Name -ErrorAction SilentlyContinue;"
      end

      def pipe_select_process
        " if ($processes) { $processes"
      end

      def pipe_filter_process
        " | ForEach-Object { $process = $_; $processDetails = Get-WmiObject -Class Win32_Process -Filter \\\"ProcessId = $($process.Id)\\\" -ErrorAction SilentlyContinue;"
      end

      # If a process is found, we will get the details of the process. Note that different processes can have different properties that can be added to the output and should be added both in the "DEFAULT_KEYS" and "pipe_select_process_details" variables.
      # The "CreationDate" property is in the "Win32_Process" class, but it is not in the "System.Diagnostics.Process" class. So, we need to convert it to a readable format.
      def pipe_select_process_details
        " if ($processDetails) { [PSCustomObject]@{ \\\"ServiceName\\\" = $service.Name; \\\"DisplayName\\\" = $service.DisplayName; \\\"Status\\\" = $service.Status; \\\"StartType\\\" = $service.StartType; \\\"ProcessID\\\" = $process.Id; \\\"ExecutablePath\\\" = $processDetails.ExecutablePath; \\\"CommandLine\\\" = $processDetails.CommandLine; \\\"CreationDate\\\" = [Management.ManagementDateTimeConverter]::ToDateTime($processDetails.CreationDate).ToString('o'); \\\"CPUTime\\\" = $processDetails.UserModeTime; \\\"MemoryUsage\\\" = [math]::Round($processDetails.WorkingSetSize / 1MB, 2) }"
      end

      # It is importante to notice that not every service has a process associated with it. Besides that, our user may not have permission to access some services and/or processes.
      # In these cases, the "Get-Process" and "Get-WmiObject" commands will return null. In this case, we need to return a null object to avoid errors.
      def pipe_select_process_null
        " } } } else { [PSCustomObject]@{ \\\"ServiceName\\\" = $service.Name; \\\"DisplayName\\\" = $service.DisplayName; \\\"Status\\\" = $service.Status; \\\"StartType\\\" = $service.StartType; \\\"ProcessID\\\" = \\\"\\\"; \\\"ExecutablePath\\\" = \\\"\\\"; \\\"CommandLine\\\" = \\\"\\\"; \\\"CreationDate\\\" = \\\"\\\"; \\\"CPUTime\\\" = \\\"\\\"; \\\"MemoryUsage\\\" = \\\"\\\" } } }"
      end

      def pipe_formatting_output
        # In the "ConvertTo-Csv" command, there are 2 lines of type info and header info at the beginning in the outputs.
        # By the "NoTypeInformation" option, the line of type info is excluded.
        # This enables you to skip the just first line for parsing, like linux or mac.
        " | ConvertTo-Csv -NoTypeInformation"
      end
    end
  end
end
