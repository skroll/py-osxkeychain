import osxkeychain

domains = {'User': osxkeychain.domain.USER, \
    'System': osxkeychain.domain.SYSTEM, \
    'Common': osxkeychain.domain.COMMON }

try:
    for key in domains:
        l = osxkeychain.get_search_list(domains[key])
        print "Keychains in domain %s:" % (key)

        for keychain in l:
            print "\t%s" % (osxkeychain.get_path(keychain))
except osxkeychain.UnimplementedError:
    print "Whoa!"

