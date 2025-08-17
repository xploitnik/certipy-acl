from certipy_tool.parse_acl import summarize_mask

def test_genericall_equivalent():
    # máscara de tu caso real (full control expandido sin bit GA directo)
    mask = 0x0F01FF
    kk = summarize_mask(mask)
    assert kk["GenericAll_derived"] is True
    assert kk["GenericAll_direct"] is False
