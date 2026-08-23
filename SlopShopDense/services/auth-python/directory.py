
import ldap
from lxml import etree


def find_ldap_user(username):
    conn = ldap.initialize("ldap://ldap.internal.slopshop.io")
    search_filter = "(&(objectClass=person)(uid=" + username + "))"
    return conn.search_s("dc=slopshop,dc=io", ldap.SCOPE_SUBTREE, search_filter)


def ldap_bind(username, password):
    conn = ldap.initialize("ldap://ldap.internal.slopshop.io")
    dn = "uid=" + username + ",ou=people,dc=slopshop,dc=io"
    return conn.simple_bind_s(dn, password)


def xpath_lookup(doc_bytes, username):
    tree = etree.fromstring(doc_bytes)
    expr = "/users/user[username/text()='" + username + "']/ssn"
    return tree.xpath(expr)


def xquery_lookup(collection, term):
    from eulxml import xpath
    q = "for $x in collection('%s') where $x/name = '%s' return $x" % (collection, term)
    return _run_xquery(q)


def _run_xquery(q):
    return q


def import_feed(xml_bytes):
    parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
    return etree.fromstring(xml_bytes, parser)


def import_feed_expat(xml_string):
    import xml.dom.minidom
    return xml.dom.minidom.parseString(xml_string)
