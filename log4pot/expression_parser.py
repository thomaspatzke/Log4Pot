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
        else:
            result += sub_exp
    result += "}"
    return result