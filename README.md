Build Instructions
==================

From the project root:

    javac -d out src/*.java

This compiles all eight .java files. Then run any of the three test/demo classes
from the output directory:

    java -cp out TestStubResolver
    java -cp out TestResolver
    java -cp out TestNameServer


Working Functionality
======================

All three classes are complete and working.

StubResolver.java
- Sends and receives UDP packets using a java.net.DatagramSocketand java.net.DatagramPacket.
- Performs recursive resolution using the DNS server given during configuration.
- Performs queries for A, NS, MX, TXT, CNAME resource records.
- Handles the case when the domain name is found and when it is not.

Resolver.java
- Performs iterative resolution starting from the DNS server given during configuration.
- Performs queries for A, NS, MX, TXT, CNAME resource records.
- Handlse challenging and error cases including unresponsive and backup servers, invalid or irrelevant responses, CNAME records found duringresolution,CNAME loops, glue records, etc.
- Handles the case when the domain name is found and when it is not.

NameServer.java
- Accepts queries from multiple simultaneous clients via UDP.
- Maintains a cache of live resource records and negative responses, including the correct TTL and removal of expired records.
- Answers queries using the cache and iterative resolution.
- Handles error conditions including invalid and malicious requests.
