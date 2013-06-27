#!/usr/bin/env ruby

require 'packetfu'
require 'hirb'
require 'pry'
require 'yaml'
require 'singleton'
require './helper'

$config = YAML.load(File.read('config.yml'))
$logger = Helper::Logger.instance.backend

Hirb.enable

module SnifferMain

  class Sniffer
    attr_accessor :flow

    def initialize(iface)
      @flow = PacketFu::Capture.new(iface: iface)
    end
  end

  local_interfaces = Helper::Interfaces.get_local_interfaces
  puts Hirb::Helpers::Table.render local_interfaces, all_fields: true, description: false, fields: [:no, :iface, :ip_saddr, :eth_saddr, :mask]

  chosen_interface = Helper::InterfaceChoser.chose_interface_to_sniff local_interfaces

  store_data_path = Helper::DataStore.data_save(chosen_interface)

  keywords = Helper::ChoseKeywords.chose_keywords_to_sniff

  if false #keywords.size > 1
    res = ''
    keywords.each { |k| res += "#{k}|" }
    keywords = res[0..-2]
  elsif false#keywords.size == 1
    "/#{keyword}/"
  else
    keywords = nil
  end

  cap = Sniffer.new chosen_interface
  cap.flow.start
  @pcaps = []
  loop do
    cap.flow.stream.each do |p|
      pkt = PacketFu::Packet.parse p
      if !pkt.nil? && pkt.is_ip?
        payload_get = Helper::PayloadDataExtractor.input_body pkt, keywords
        packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.size, pkt.proto.last]
        if payload_get.size > 0
          catched = "%-15s -> %-15s %-4d %s" % packet_info + ' >>>>>> ' + payload_get.inspect
          File.open('captured/catched.txt', 'a') { |file| file.write(catched+"\n") }
          puts catched
        else
          puts "%-15s -> %-15s %-4d %s" % packet_info
        end
      end
      @pcaps << p
      if @pcaps.size > 1000
        pfile = PacketFu::PcapFile.new
        res = pfile.a2f(filename: store_data_path, array: @pcaps, append: true)
        @pcaps.clear
        puts 'Packets stored to filesystem'
      end
    end
  end

end

