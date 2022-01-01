# Deobfuscate and parse Log4j lookups

import re

def deobfuscate(expr : str) -> str:
    if expr.startswith("${"):      # The expression is a lookup, handle it.
        try:
            pos_end = expr.index("}")
        except ValueError:          # no end, no valid lookup, pass it back
            return expr

        try:
            pos_lookup = expr.index("${", 2)   # position of next lookup
        except ValueError:      # no further lookup found
            pos_lookup = None

        if pos_lookup is not None and pos_lookup < pos_end:         # there's a lookup before the potential end: resolve it first and possible following lookup expressions
            return deobfuscate(expr[:pos_lookup] + deobfuscate(expr[pos_lookup:pos_end + 1]) + deobfuscate(expr[pos_end + 1:]))
        else:       # Handling of expressions
            try:
                pos_colon = expr.index(":")
                lookup_type = expr[2:pos_colon].lower()
            except ValueError:      # ${...something without a colon} - return expression
                return expr

            try:
                pos_value = expr.index(":-") + 2
            except ValueError:
                pos_value = None

            if lookup_type == "jndi":       # JNDI lookup - return lower cased
                return "${jndi" + expr[6:]
            elif lookup_type in ("lower", "upper"):    # lower/upper case lookups
                return expr[pos_colon + 1:pos_end].__getattribute__(lookup_type)() + deobfuscate(expr[pos_end + 1:])
            elif pos_value is not None and pos_value < pos_end:       # ${...:-value} - return value
                return expr[pos_value:pos_end] + deobfuscate(expr[pos_end + 1:])
            else:       # everything else: return value after colon, e.g. ${env:foo} -> foo
                return expr[pos_colon + 1:pos_end] + deobfuscate(expr[pos_end + 1:])
    else:           # the expression is (not yet) a lookup: pass the prefix and process possibly existing lookups
        try:
            pos_expr = expr.index("${")
            return expr[:pos_expr] + deobfuscate(expr[pos_expr:])
        except ValueError:      # no lookup contained, pass string back
            return expr