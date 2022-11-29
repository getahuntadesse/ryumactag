# ryumactag
The Following are modified source code to include additional TLV known as MacTag and it is to indicate that specifically where the source code is modified or updated. 
lldp.py (ryu/lib/packet/lldp.py)
in this file I need to add Add TLV type , Add MacTag class and Modify lldp class 
1.	add a TLV type: MAC_TAG
# LLDP TLV types
LLDP_TLV_MACTAG = 12 			#  MACTAG for sending LLDP packet, using HMAC  
2.	add MacTag class
The TTL class reference lldp.py
@lldp.set_tlv_type(LLDP_TLV_SEND_TIME)
class MacTag(LLDPBasicTLV):
    _PACK_STR = '!d'  # double because the digested message is 8 byte long
    _PACK_SIZE = struct.calcsize(_PACK_STR)
    _LEN_MIN = _PACK_SIZE
    _LEN_MAX = _PACK_SIZE

    def __init__(self, buf=None, *args, **kwargs):
        super(MacTag, self).__init__(buf, *args, **kwargs)
        if buf:
            (self.mactag, ) = struct.unpack(
                self._PACK_STR, self.tlv_info[:self._PACK_SIZE])
        else:
            self.mactag = kwargs['mactag']
            self.len = self._PACK_SIZE
            assert self._len_valid()
            self.typelen = (self.tlv_type << LLDP_TLV_TYPE_SHIFT) | self.len

    def serialize(self):
        return struct.pack('!Hd', self.typelen, self.mactag)
3.	Modify lldp class
Removing the last one, i.e., a final determination is not END
def _tlvs_valid(self):
    return (self.tlvs[0].tlv_type == LLDP_TLV_CHASSIS_ID and
      self.tlvs[1].tlv_type == LLDP_TLV_PORT_ID and
      self.tlvs[2].tlv_type == LLDP_TLV_TTL)
Modify the break conditions
def _parser(cls, buf)
    tlvs = []
    while buf:
        tlv_type = LLDPBasicTlv.get_type(buf)
        tlv = cls._tlv_parsers[tlv_type](buf)
        tlvs.append(tlv)
        offset = LLDP_TLV_SIZE + tlv.len
        buf = buf[offset:]
        if tlv.tlv_type == LLDP_TLV_MACTAG: # END changed LLDP_TLV_MACTAG
            break
        assert len(buf) > 0
    lldp_pkt = cls(tlvs)
    assert lldp_pkt._tlvs_len_valid()
    assert lldp_pkt._tlvs_valid()
    return lldp_pkt, None, buf
switches.py: ryu/topology/switches
1.import hmac and hashlib to compute hmac over dpid, port_id, port_hrdw_addr
2.switches.py file LLDPPacket class initialization is completed and the sequence of data packets to achieve LLDP
3.The method may be configured lldp_packet LLDP packet, and return data after serialization. In this function, I added the TLV mactag
4.lldp_parse: The data obtained for the analysis of the byte stream corresponding LLDP packets, since before sending, I added a mactag of TLV, it is necessary to perform the parsing of the parsing TLV, and returned as a return value mactag
1.	@static method lldp_packet
Parameters magtag 
 add methods
def lldp_packet(dpid, port_no, dl_addr, ttl, mactag): # added additional tlv called mactag
add mactag property
tlv_ttl = lldp.TTL(ttl=ttl)
tlv_mactag = lldp.MacTag(mactag=mactag)
tlv_end = lldp.End()
Modify tlvs: add a mactag parameters
tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_mactag, tlv_end)
2.	switches.py：@staticmethod lldp_parse
tlv_mactag = lldp_pkt.tlvs[3]
mactag = tlv_mactag
return  src_dpid, src_port_no, mactag
3.	def _port_added Review: increase mactag
def _port_added(self, port):
    key = "E49756B4C8FAB4E48222A3E7F3B97CC3"
        message = dpid_to_str(port.dpid)
        key = bytes(key, 'UTF-8')
        message = bytes(message, 'UTF-8')
        mactag = hmac.new(key, message).hexdigest().upper()
        mac_tag = bytes(mactag, 'UTF-8')
        mac_tag_int = int.from_bytes(mac_tag,byteorder="little", signed=False)
        lldp_data = LLDPPacket.lldp_packet(port.dpid, port.port_no, port.hw_addr, self.DEFAULT_TTL, mac_tag_int)
 


Second place:
LLDP_PACKET_LEN = len(LLDPPacket.lldp_packet(0, 0, DONTCARE_STR, 0, 0))
switches.py: add a variable return
Lldp_parse method called the place, the value returned should add a mactag
src_dpid, src_port_no, mactag = LLDPPacket.lldp_parse(msg.data)
LLDP packet sending a modification, each mactag reinserted
  def send_lldp_packet(self, port):
    try:
      port_data = self.ports.lldp_sent(port)
    except KeyError:
      # ports can be modified during our sleep in self.lldp_loop()
      # LOG.debug('send_lld error', exc_info=True)
      return
    if port_data.is_down:
      return

    dp = self.dps.get(port.dpid, None)
    if dp is None:
      # datapath was already deleted
      return
    # added part
    key = "E49756B4C8FAB4E48222A3E7F3B97CC3"
        message = dpid_to_str(port.dpid)
        key = bytes(key, 'UTF-8')
        message = bytes(message, 'UTF-8')
        mactag = hmac.new(key, message).hexdigest().upper()
        # mactag = base64.urlsafe_b64encode(mactag)
        mac_tag = bytes(mactag, 'UTF-8')
        mac_tag_int = int.from_bytes(mac_tag,byteorder="little", signed=False)
        lldp_data = LLDPPacket.lldp_packet(port.dpid, port.port_no, port.hw_addr, self.DEFAULT_TTL, mac_tag_int)
 
    # LOG.debug('lldp sent dpid=%s, port_no=%d', dp.id, port.port_no, mac_tag_int)
    # TODO:XXX
    if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
      actions = [dp.ofproto_parser.OFPActionOutput(port.port_no)]
      dp.send_packet_out(actions=actions, data=lldp_data)
    elif dp.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
      actions = [dp.ofproto_parser.OFPActionOutput(port.port_no)]
      out = dp.ofproto_parser.OFPPacketOut(
        datapath=dp, in_port=dp.ofproto.OFPP_CONTROLLER,
        buffer_id=dp.ofproto.OFP_NO_BUFFER, actions=actions,
        data=lldp_data)
      dp.send_msg(out)
    #print port_data #cat
    else:
      LOG.error('cannot send lldp packet. unsupported version. %x',
            dp.ofproto.OFP_VERSION)

As well as: data out of the assignment was changed lldp_data
      out = dp.ofproto_parser.OFPPacketOut(
        datapath=dp, in_port=dp.ofproto.OFPP_CONTROLLER,
        buffer_id=dp.ofproto.OFP_NO_BUFFER, actions=actions,
        data=lldp_data)

Third, verify
Print time stamp
lldp_packet_in_handler callback function:
increase the printing message:
try:
    src_dpid, src_port_no, mactag = LLDPPacket.lldp_parse(msg.data)
   


N.B The highlighted code is either modified or added 
