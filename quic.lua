do
    local p_quic = Proto ("quic_http3", "Quic proto for http3")

    local f = p_quic.fields

    f.f_quic_version = ProtoField.uint32 ("quic.version","QUIC Version")
    f.f_quic_long_package_flag = ProtoField.uint8 ("quic.long_package_flag","long package Flag", base.DEC, nil, 0x80)
    f.f_quic_DCIL = ProtoField.uint8 ("quic.DCIL","Dst Connection ID Len", base.DEC, nil, 0xf0)
    f.f_quic_real_DCIL = ProtoField.uint8 ("quic.DCIL","Dst Connection ID Len after cal")
    f.f_quic_real_SCIL = ProtoField.uint8 ("quic.SCIL","Src Connection ID Len after cal")
    f.f_quic_SCIL = ProtoField.uint8 ("quic.SCIL","Src Connection ID Len", base.DEC, nil, 0x0f)
    f.f_quic_SCI = ProtoField.uint32 ("quic.SCI","Src Connection ID")
    f.f_quic_DCI = ProtoField.uint32 ("quic.DCI","Dst Connection ID")

    function p_quic.dissector(tvb, pinfo, tree)
        pinfo.cols.protocol = "QUIC/HTTP3.0"
        local subtree = tree:add (p_quic, tvb())
        local offset = 0

        local first_oct = tvb(offset, 1)
        offset = offset + 1
        subtree:add (f.f_quic_long_package_flag, 0xf0)
        local version = tvb(offset, 4)
        offset = offset + 4
        subtree:add (f.f_quic_version, version)

        local CI_len = tvb(offset, 1)
        offset = offset + 1
        subtree:add (f.f_quic_DCIL, CI_len)
        subtree:add (f.f_quic_SCIL, CI_len)

        local DCIL = bit32.rshift(bit32.band(CI_len:uint(), 0xf0), 4)
        local SCIL = bit32.band(CI_len:uint(), 0x0f)
        if(DCIL > 0) then
            subtree:add (f.f_quic_real_DCIL, DCIL + 3)
            local dst_connection_id = tvb(offset, DCIL + 3)
            offset = offset + 3 + DCIL
            subtree:add (f.f_quic_DCI, dst_connection_id)
        else
            subtree:add (f.f_quic_real_DCIL, DCIL)
        end
        if(SCIL > 0) then
            subtree:add (f.f_quic_real_SCIL, SCIL + 3)
            local src_connection_id = tvb(offset, SCIL + 3)
            offset = offset + 3 + SCIL
            subtree:add (f.f_quic_SCI, src_connection_id)
        else
            subtree:add (f.f_quic_real_SCIL, SCIL)
        end

    end

    -- Register the dissector
    local udp_encap_table = DissectorTable.get("udp.port")
    udp_encap_table:add(6162,p_quic)
end
