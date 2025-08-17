RIGHTS = {
    0x00000001: "ReadProperty",
    0x00000002: "WriteProperty",
    0x00000004: "CreateChild",
    0x00000008: "DeleteChild",
    0x00000010: "ListChildren",
    0x00000020: "Self",
    0x00000040: "ReadControl",
    0x00000100: "Delete",
    0x00020000: "WriteDACL",
    0x00080000: "WriteOwner",
    0x01000000: "GenericRead",
    0x02000000: "GenericWrite",
    0x04000000: "GenericExecute",
    0x08000000: "GenericAll",
}

KEY_RIGHTS = {"WriteOwner", "WriteDACL", "GenericAll", "GenericWrite"}
