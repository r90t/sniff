#!/usr/bin/env ruby

module Helper

  class Logger

    require 'log4r'
    require 'log4r/yamlconfigurator'

    include Singleton

    attr_reader :backend
    
    def initialize
      if @backend.nil?
        Log4r::YamlConfigurator.decode_yaml $config['log4r_config']
        @backend = Log4r::Logger['Sniffer']
      end
    end

  end

  class Interfaces

    def self.get_local_interfaces

      require 'active_support/core_ext/hash'

      ifaces = get_interfaces_list
      unless ifaces.nil? || ifaces.size < 1
        res = []
        cnt = 0
        ifaces.each do |i|
          res << interface_data_extractor((PacketFu::Utils.ifconfig i), cnt)
          cnt += 1
        end
        res
      else
        $logger.error 'There is no network interfaces on machine'
      end
    end

    private

    def self.get_interfaces_list
      res = %x{ifconfig -a | sed 's/[ \t].*//;/^\(lo\|\)$/d'}
      res.nil? ? nil : res.split(/\W+/)
    end

    def self.interface_data_extractor(iface, cnt)
     iface.except!(:ip6_saddr, :ip6_obj, :eth_src, :ip_src)
     unless iface[:ip4_obj].nil?
       iface[:mask] = iface[:ip4_obj].inspect[/\/\d*\.\d*\.\d*\.\d*/i][1..-1]
       iface.delete(:ip4_obj) 
     end
     iface[:no] = cnt
     iface
    end

  end

  class InterfaceChoser
    def self.chose_interface_to_sniff(interfaces)
      puts 'Please chose the interface to listen on. Type the number of interface from no field or type exit to exit: '
      iface = nil
      while iface.nil?
        input = gets.chomp
        exit if input.downcase == 'exit'
        interfaces.each { |i| iface = i[:iface] if i[:no].to_s == input.to_s }
        puts 'Please select right interface number or exit' if iface.nil?
      end
      iface
    end
  end

  class DataStore
    def self.data_save(iface)
      puts "The data will be stored in the pcap file. You have to chose directory for storing results.\n Please leave empty string to store data in app/captured or write your own place like dirname/:"
      file_name = generate_file_name(iface)
      res = nil
      while res.nil?
        input = gets.chomp
        exit if input == 'exit'
        if input.empty?
          puts 'You chose default datastore path in app/captured folder.'
          res = "captured/"
          res = nil unless check_write_access?(res)
          puts 'Please check write access to app/captured folder and try again or type exit to exit from app' if res.nil?
          res
        else
          puts "You chose #{input} direcotry."
          res = input.to_s
          res = nil unless check_write_access?(res)
          puts "Please check write access to #{input} folder or type exit to exit" if res.nil?
          res
        end
      end
      puts "Capture will be stored in dir: #{res} with filename: #{file_name}."
      (res + file_name)
    end

    private

    def self.generate_file_name(iface)
      (Time.now.to_s.tr(' ', '_') + "-#{iface}" + ".pcap")
    end

    def self.check_write_access?(path)
      return File.writable?(path)
    end
  end

  class ChoseKeywords
    def self.chose_keywords_to_sniff
      puts 'Please setup the keywords which will alert app to store the packet in file for ex. "keyword1, keyword2, keyword3, keyword4 ..." or leave blank for capture all'
      res = nil
      while res.nil?
        input = gets.chomp
        exit if input == 'exit'
        unless input.empty?
          res = input.split(/[\s,]+/)
          unless res.kind_of?(Array)
            puts 'Please input valid string like "keyword1, keyword2, keyword3 ..." or leave line empty to capture all. To exit type exit.'
          end
          res if !res.nil?
        else
          res = '' if input.empty?
        end
      end
      res.empty? ? nil : res
    end
  end

  class PayloadDataExtractor
    def self.input_body(pkt, keywords = nil)
      result = nil
      result = pkt.payload.scan(/(user(?:name)|login|e(?:mail)|p(?:ass(?:word|wd|)|w|wd))[\s:=]\s?([^\&\s]*)/i)
     # unless keywords.nil?
        #result << pkt.payload.scan(keywords)
     #   binding.pry
     # end
      result
    end
  end
end
