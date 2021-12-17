# Deobfuscate and parse Log4j lookups

import re

def resolve(expr):
    if expr.startswith("${"):      # The expression is a lookup, handle it.
        try:
            pos_end = expr.index("}")
        except ValueError:          # no end, no valid lookup, pass it back
            return expr

        try:
            pos_lookup = expr.index("${")   # position of next lookup
        except ValueError:      # no further lookup found
            pos_lookup = None

        if pos_lookup is not None and pos_lookup < pos_end:         # there's a lookup before the potential end: resolve it first

    else:           # the expression is (not yet) a lookup: pass the prefix and process possibly existing lookups
        try:
            i = expr.index("${")
            return expr[:i] + resolve(expr[i:])
        except ValueError:      # no lookup contained, pass string back
            return expr









re_lookup_start = re.compile("\${\s*(?P<type>\w+)\s*:")
re_lookup_with_nesting = re.compile("[^}]*\${")

def resolve_old(expr):
    """Parses recursively the Log4j lookup expression. Keep JNDI expressions for further processing."""
    if expr.startswith("${"):      # The expression is a lookup, handle it.
        m : re.Match = re_lookup_type.search(expr)
        if not m:       # Something that couldn't be parsed: parse remainder and return ${ + parsed result
            return "${" + resolve(expr[2:])
        else:           # successfully parsed beginning of lookup expression
            # First check if there are nested lookup expressions and resolve them before processing continues
            prefix = expr[:m.end()]
            rem = expr[m.end():]
            mn = re_lookup_with_nesting.search(rem)
            if mn is None:      # no nested lookups
                endpos =

            # Keep JNDI expressions, resolve everything else to a value.
            if m.group("type").lower() == "jndi":
                pass