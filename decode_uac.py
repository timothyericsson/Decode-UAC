#!/usr/bin/env python3
"""
decode_uac.py
Ask for an Active Directory userAccountControl value and print the enabled flags.
Quit with blank Enter, Ctrl+C, Ctrl+D, or by typing q, quit, exit, or :q
"""

UAC_FLAGS = {
    0x00000001: "SCRIPT",
    0x00000002: "ACCOUNTDISABLE",
    0x00000008: "HOMEDIR_REQUIRED",
    0x00000010: "LOCKOUT",
    0x00000020: "PASSWD_NOTREQD",
    0x00000040: "PASSWD_CANT_CHANGE",
    0x00000080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x00000100: "TEMP_DUPLICATE_ACCOUNT",
    0x00000200: "NORMAL_ACCOUNT",
    0x00000800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x00001000: "WORKSTATION_TRUST_ACCOUNT",
    0x00002000: "SERVER_TRUST_ACCOUNT",
    0x00010000: "DONT_EXPIRE_PASSWORD",
    0x00020000: "MNS_LOGON_ACCOUNT",
    0x00040000: "SMARTCARD_REQUIRED",
    0x00080000: "TRUSTED_FOR_DELEGATION  (classic unconstrained flag)",
    0x00100000: "NOT_DELEGATED",
    0x00200000: "USE_DES_KEY_ONLY",
    0x00400000: "DONT_REQ_PREAUTH",
    0x00800000: "PASSWORD_EXPIRED",
    0x01000000: "TRUSTED_TO_AUTH_FOR_DELEGATION  (Protocol Transition enabled)",
    0x04000000: "PARTIAL_SECRETS_ACCOUNT",
}

DELEGATION_HINTS = {
    "PT": 0x01000000,
    "UNCONSTRAINED": 0x00080000,
}

def parse_uac(inp: str) -> int:
    s = inp.strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    return int(s, 10)

def explain(uac: int) -> None:
    print(f"\nDecoded userAccountControl:")
    print(f"  Decimal: {uac}")
    print(f"  Hex:     0x{uac:08x}\n")

    enabled = [desc for bit, desc in UAC_FLAGS.items() if uac & bit]
    if not enabled:
        print("No known UAC flags are set.")
    else:
        print("Enabled flags:")
        for desc in enabled:
            print(f"  - {desc}")

    pt_on  = bool(uac & DELEGATION_HINTS["PT"])
    uc_on  = bool(uac & DELEGATION_HINTS["UNCONSTRAINED"])

    print("\nDelegation quick view:")
    print(f"  Protocol Transition: {'ON' if pt_on else 'OFF'}")
    print(f"  Unconstrained flag:  {'ON' if uc_on else 'OFF'}")

    print("\nNotes:")
    print("  - Constrained targets are in msDS-AllowedToDelegateTo.")
    print("  - RBCD lives on the target in msDS-AllowedToActOnBehalfOfOtherIdentity.\n")

def main():
    print("Active Directory UAC decoder")
    print("Enter a userAccountControl value in decimal or hex (example: 17305600 or 0x1081000).")
    print("Quit with blank Enter, Ctrl+C, Ctrl+D, or type q, quit, exit, or :q.\n")

    while True:
        try:
            inp = input("UAC value> ").strip()
        except EOFError:
            break
        except KeyboardInterrupt:
            print("\nInterrupted.")
            break

        if not inp:
            break
        if inp.lower() in {"q", "quit", "exit", ":q"}:
            break

        try:
            uac = parse_uac(inp)
        except ValueError:
            print("Could not parse number. Try: 17305600 or 0x1081000")
            continue

        explain(uac)

    print("\nDone.")

if __name__ == "__main__":
    main()
