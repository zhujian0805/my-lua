do
 local p_vxlan = Proto("vxlan","Virtual eXtended LAN");

 local f_flags = ProtoField.uint8("vxlan.flags","Flags",base.HEX)
 local f_flag_i = ProtoField.bool("vxlan.flags.i","I Flag",8,
   {"Valid VNI Tag present", "Valid VNI Tag NOT present"}, 0x08)
 local f_rsvd1 = ProtoField.uint24("vxlan.rsvd1","Reserved",
   base.HEX)
 local f_vni = ProtoField.uint24("vxlan.vni","VNI",base.HEX)
 local f_rsvd2 = ProtoField.uint8("vxlan.rsvd2","Reserved",
   base.HEX)

 p_vxlan.fields = {f_flags, f_flag_i, f_rsvd1, f_vni, f_rsvd2}

 function p_vxlan.dissector(buf, pinfo, root)

   local t = root:add(p_vxlan, buf(0,8))

   local f = t:add(f_flags, buf(0,1))
   f:add(f_flag_i, buf(0,1))

   t:add(f_rsvd1, buf(1,3))
   t:add(f_vni, buf(4,3))
   t:add(f_rsvd2, buf(7,1))

   t:append_text(", VNI: 0x" .. string.format("%x", 
      buf(4, 3):uint()))

   local eth_dis = Dissector.get("eth")
   eth_dis:call(buf(8):tvb(), pinfo, root)
 end

 local udp_encap_table = DissectorTable.get("udp.port")
 udp_encap_table:add(9029, p_vxlan)
end