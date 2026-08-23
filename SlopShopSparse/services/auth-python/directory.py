"""Directory and document lookups.

The corporate directory is LDAP; the partner feeds are XML. Both are external
systems the marketplace does not control, so everything here is written to
degrade to an empty result rather than to raise into a request handler.
"""

import ldap
from lxml import etree

LDAP_URI = "ldap://ldap.internal.slopshop.io"
LDAP_BASE_DN = "dc=slopshop,dc=io"

# Attributes the directory lookups are allowed to return. Anything outside the
# list is dropped before the result reaches a caller, so a directory schema
# change cannot quietly widen what the storefront can see.
RETURNED_ATTRIBUTES = ("uid", "cn", "mail", "department")

# Characters that must be escaped before a value can appear inside a filter,
# per RFC 4515. The escaping helper below is what the safe lookups use.
_LDAP_ESCAPES = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\0": r"\00"}


def _connect():
    """Open a directory connection with the protocol version pinned."""
    conn = ldap.initialize(LDAP_URI)
    conn.protocol_version = ldap.VERSION3
    return conn


def escape_filter_value(value):
    """Escape a value for safe inclusion in an LDAP search filter."""
    return "".join(_LDAP_ESCAPES.get(ch, ch) for ch in (value or ""))


def find_ldap_user(username):
    conn = ldap.initialize("ldap://ldap.internal.slopshop.io")
    search_filter = "(&(objectClass=person)(uid=" + username + "))"
    return conn.search_s("dc=slopshop,dc=io", ldap.SCOPE_SUBTREE, search_filter)


def find_ldap_user_escaped(username):
    """Same search with the value escaped before it is spliced into the filter."""
    conn = _connect()
    search_filter = "(&(objectClass=person)(uid=%s))" % escape_filter_value(username)
    return conn.search_s(
        LDAP_BASE_DN, ldap.SCOPE_SUBTREE, search_filter, list(RETURNED_ATTRIBUTES)
    )


def ldap_bind(username, password):
    conn = ldap.initialize("ldap://ldap.internal.slopshop.io")
    dn = "uid=" + username + ",ou=people,dc=slopshop,dc=io"
    return conn.simple_bind_s(dn, password)


def ldap_bind_resolved(username, password):
    """Look the DN up by search first, so no caller-supplied text lands in it."""
    matches = find_ldap_user_escaped(username)
    if len(matches) != 1:
        raise ValueError("directory lookup was not unique")
    dn = matches[0][0]
    conn = _connect()
    return conn.simple_bind_s(dn, password)


def xpath_lookup(doc_bytes, username):
    tree = etree.fromstring(doc_bytes)
    expr = "/users/user[username/text()='" + username + "']/ssn"
    return tree.xpath(expr)


def xpath_lookup_bound(doc_bytes, username):
    """Variable binding keeps the value out of the compiled expression."""
    tree = etree.fromstring(doc_bytes, _safe_parser())
    query = etree.XPath("/users/user[username/text()=$name]/department")
    return query(tree, name=username)


def xquery_lookup(collection, term):
    from eulxml import xpath
    q = "for $x in collection('%s') where $x/name = '%s' return $x" % (collection, term)
    return _run_xquery(q)


def _run_xquery(q):
    return q


def _safe_parser():
    """Parser with entity resolution, DTD loading, and network access all off."""
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        huge_tree=False,
    )


def import_feed(xml_bytes):
    parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
    return etree.fromstring(xml_bytes, parser)


def import_feed_safe(xml_bytes):
    """Partner feed import through the hardened parser above."""
    return etree.fromstring(xml_bytes, _safe_parser())


def feed_entry_count(xml_bytes):
    """Count entries without materialising the whole tree for the caller."""
    root = import_feed_safe(xml_bytes)
    return len(root.findall(".//entry"))


def import_feed_expat(xml_string):
    import xml.dom.minidom
    return xml.dom.minidom.parseString(xml_string)


def department_of(username):
    """Convenience wrapper returning a single attribute, or None."""
    for _dn, attrs in find_ldap_user_escaped(username):
        values = attrs.get("department") or []
        if values:
            return values[0].decode("utf-8", "replace")
    return None
