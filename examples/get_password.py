import sys
import osxkeychain

if not len(sys.argv) == 3:
    print "Usage: get_password.py <server> <account>"
    sys.exit()

server = sys.argv[1]
account = sys.argv[2]

print osxkeychain.find_internet_password(server, account)
