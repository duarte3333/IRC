# IRC

### IRC (Internet Relay Chat):

IRC is a text-based communication protocol used for real-time chat and messaging.
It allows users to join channels, send private messages, and participate in group discussions.

### IRC Server:

An IRC server is a program that manages connections between IRC clients. It facilitates the exchange of messages among clients.

### IRC Client:

An IRC client is a program or application that connects to an IRC server to send and receive messages. Users interact with the IRC server through the client.

### What is a socket?

A way to speak to other programs using standard Unix file descriptors.

### Stream Sockets

All the characters you type need to arrive in the same order you type them.

**Applications:**

telnet or ssh applications.

web browsers use the Hypertext Transfer Protocol (HTTP) which uses stream sockets to get page

Data quality → Protocol used is TCP (The Transmission Control Protoco) → make sure data arrives sequentially and error-free.

### Datagram Sockets

Datagram sockets also use IP for routing, but they don’t use TCP; they use the “User Datagram Protocol”,
or “UDP”.

Dont need to maintain a **open connection.**

You just build a packet, slap an IP header on it with destination information, and send it out.

tftp protocol says that for each packet that gets sent, the recipient has to send back a packet that says, “I got it!” (an “ACK” packet).

Used for **speed!** It’s way faster to fire-and-forget than it is to keep track of what has arrived safely

### The network layers of HTTP/IP

<p align="center">
  <img src="https://github.com/duarte3333/IRC/assets/76222459/72037a66-f910-481e-b4c6-55ed0992197e" alt="Image Description" style="width: 60%;">
</p>

Assign the information to a given port, for TCP knows where the data come from.

<p align="center">
  <img src="https://github.com/duarte3333/IRC/assets/76222459/63b94914-0f04-43e4-a542-5df2bcfef935" alt="Image Description" style="width: 60%;">
</p>

TCP transforms the data into packages and send them in the most efficient way.

<p align="center">
  <img src="https://github.com/duarte3333/IRC/assets/76222459/58c9d935-6ba3-4e27-a17d-0b10d0d41e86" alt="Image Description" style="width: 60%;">
</p>

In the **internet layer** the origin and destination IP are known for the package know where it came from and where it’s going.

The **network layer** make possible for the package to go to the correct physical machine. And only receive if it correspond to their MAC address.

<p align="center">
  <img src="https://github.com/duarte3333/IRC/assets/76222459/704620aa-c75a-484c-88a4-37e6032b6966" alt="Image Description" style="width: 40%;">
</p>

### MAC address

A MAC (Media Access Control) address is a unique identifier assigned to a network interface controller (NIC) for use as a network address in communications within a network segment. It is a **hardware address** that is usually assigned by the manufacturer and is used at the data link layer of the OSI model for networking.

### **DSL (Digital Subscriber Line)**

DSL is a technology that provides high-speed internet access over traditional telephone lines, allowing simultaneous data and voice communication.

### **HTTP (Hypertext Transfer Protocol)**

HTTP is the foundation of data communication on the World Wide Web, enabling the 
transfer of hypertext (linked web pages) between clients and servers.

### **ISP (Internet Service Provider):**

An ISP is a company that provides users with access to the internet, offering services such as internet connectivity, email, and web hosting.

### **DNS (Domain Name System):**

DNS is a decentralized system that translates human-readable domain names (e.g., [www.example.com](http://www.example.com/)) into IP addresses, allowing computers to locate and connect to each other on the internet.

### Private (Or Disconnected) Networks

The firewall translates “internal” IP addresses to “external” (that everyone else in the
world knows) IP addresses using a process called Network Address Translation, or NAT.

Common ones you’ll see are 10.x.x.x and 192.168.x.x where x is 0-255. Less common is 172.y.x.x, where y goes between 16 and 31.

### Data encapsulation

<p align="center">
  <img src="https://github.com/duarte3333/IRC/assets/76222459/e4588338-e110-463a-a327-af6c8da00e67" alt="Image Description" style="width: 70%;">
</p>

Layered model with unix:

- Application Layer (telnet, ftp, etc.)
- Host-to-Host Transport Layer (TCP, UDP)
- Internet Layer (IP and routing)
- Network Access Layer (Ethernet, wi-fi, or whatever)

### IPv4 addresses

In **IPv4**, it had addresses made up of four bytes (A.K.A. four “octets”),

example: 192.0.2.111

Things were great, until some naysayer by the name of Vint
Cerf warned everyone that we were about to run out of IPv4 addresses!

### IPv6 addresses

Well, the difference between 32 bits and 128 bits might not sound like a lot; it’s only 96 more bits, right? But remember, we’re talking powers here. 

hexadecimal representation, with each two-byte chunk separated by a colon

2001:0db8:c9d2:0012:0000:0000:0000:0051
2001:db8:c9d2:12::51

### Subnets

This first part of this IP address up through this bit is the network portion of the IP address, and the remainder is the host portion.

### Netmask

255.255.255.0. (E.g. with that netmask, if your IP is 192.0.2.12, then your network is 192.0.2.12 AND 255.255.255.0 which gives 192.0.2.0.).

### Port numbers

Think of the IP address as the street address of a hotel, and the port number as the room number.

![Untitled(7)](https://github.com/duarte3333/IRC/assets/76222459/ed2b0538-4974-47db-b087-ea303ad51f13)

HTTP (the web) is port 80, telnet is port 23, SMTP is port 25, the game DOOM4 used port 666.

### Byte Order

**Little-Endian / Host Byte Order** - reverse order storage

**Big-Endian / Network Byte Order** - normal order storage

note: short (two bytes) and long (four bytes)

<p align="center">
  <img src="https://github.com/duarte3333/IRC/assets/76222459/a6bf6492-09b0-41cd-a771-1fcac8cbed68" alt="Image Description" style="width: 70%;">
</p>

### Structs

**struct addrinfo** - used to prep the socket address structures for subsequent us

```cpp
struct addrinfo {
	int ai_flags; // AI_PASSIVE, AI_CANONNAME, etc.
	int ai_family; // AF_INET, AF_INET6, AF_UNSPEC
	int ai_socktype; // SOCK_STREAM, SOCK_DGRAM
	int ai_protocol; // use 0 for "any"
	size_t ai_addrlen; // size of ai_addr in bytes
	struct sockaddr *ai_addr; // struct sockaddr_in or _in6
	char *ai_canonname; // full canonical hostname
	struct addrinfo *ai_next; // linked list, next node
};
```

Load this struct up a bit, and then call getaddrinfo(). It’ll return a pointer to a new linked list of these structures filled out with all the goodies you need

```cpp
struct sockaddr {
	unsigned short sa_family; // address family, AF_xxx
	char sa_data[14]; // 14 bytes of protocol address
};
```

sa_family can be a variety of things, but it’ll be AF_INET (IPv4) or AF_INET6 (IPv6).

sa_data contains a destination address and port number for the socket.

For **IPv4:**

```cpp
struct sockaddr_in {
	short int sin_family; // Address family, AF_INET
	unsigned short int sin_port; // Port number, must be in network byte order
	struct in_addr sin_addr; // Internet address
	unsigned char sin_zero[8]; // Same size as struct sockaddr
};
```

This structure makes it **easy** to reference elements of the socket address. Is possible to cast  a struct sockaddr_in to a pointer to of a struct sockaddr and vice-versa.

```cpp
// Internet address (a structure for historical reasons)
struct in_addr {
	uint32_t s_addr; // that's a 32-bit int (4 bytes)
};
```

For **IPv6:**

```cpp
// (IPv6 only--see struct sockaddr_in and struct in_addr for IPv4)
struct sockaddr_in6 {
	u_int16_t sin6_family; // address family, AF_INET6
	u_int16_t sin6_port; // port number, Network Byte Order
	u_int32_t sin6_flowinfo; // IPv6 flow information
	struct in6_addr sin6_addr; // IPv6 address
	u_int32_t sin6_scope_id; // Scope ID
};
struct in6_addr {
	unsigned char s6_addr[16]; // IPv6 address
};
```

Another approach:

```cpp
struct sockaddr_storage {
	sa_family_t ss_family; // address family
	// all this is padding, implementation specific, ignore it:
	char __ss_pad1[_SS_PAD1SIZE];
	int64_t __ss_align;
	char __ss_pad2[_SS_PAD2SIZE];
};
```

Also possible to cast.

**Converts an IP address in numbers-and-dots notation into either a struct in_addr:**

```cpp
struct sockaddr_in sa; // IPv4
struct sockaddr_in6 sa6; // IPv6
inet_pton(AF_INET, "10.12.110.57", &(sa.sin_addr)); // IPv4
inet_pton(AF_INET6, "2001:db8:63b3:1::3490", &(sa6.sin6_addr)); // IPv6
```

“pton” stands for “presentation to network”.

**Other way around, from struct in_addr to numbers and dots notation:**

```cpp
// IPv4:

char ip4[INET_ADDRSTRLEN]; // space to hold the IPv4 string
struct sockaddr_in sa; // pretend this is loaded with something
inet_ntop(AF_INET, &(sa.sin_addr), ip4, INET_ADDRSTRLEN);
printf("The IPv4 address is: %s\n", ip4);

// IPv6:

char ip6[INET6_ADDRSTRLEN]; // space to hold the IPv6 string
struct sockaddr_in6 sa6; // pretend this is loaded with something
inet_ntop(AF_INET6, &(sa6.sin6_addr), ip6, INET6_ADDRSTRLEN);
printf("The address is: %s\n", ip6);
```

“ntop” means “network to presentation.

### First script

Print the IP addresses for whatever host you specify on the command line

### socket() - Get the File Descriptor!

```cpp
#include <sys/types.h>
#include <sys/socket.h>
int socket(int domain, int type, int protocol);
```

arguments: (IPv4 or IPv6, stream or datagram, and TCP or UDP

```cpp
int s;
struct addrinfo hints, *res;
// do the lookup
// [pretend we already filled out the "hints" struct]
getaddrinfo("www.example.com", "http", &hints, &res);

// again, you should do error-checking on getaddrinfo(), and walk
// the "res" linked list looking for valid entries instead of just
// assuming the first one is good (like many of these examples do).
// See the section on client/server for real examples.
s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
```

socket() simply returns to you a socket descriptor that you can use in later system calls.

### bind() - What port am I on?

Associates a socket (identified by `sockfd`) with a specific local address and port defined by the `my_addr` structure.

The port number is used by the kernel to match an incoming packet to a certain process’s socket descriptor.

```cpp
#include <sys/types.h>
#include <sys/socket.h>
int bind(int sockfd, struct sockaddr *my_addr, int addrlen);
```

sockfd is the socket file descriptor returned by socket(). 

my_addr is a pointer to a struct sockaddr that contains information about your address, namely, port and IP address. addrlen is the length in bytes of that address

**Note:** By using the AI_PASSIVE flag, I’m telling the program to bind to the IP of the host it’s running on. If you want to bind to a specific local IP address, drop the AI_PASSIVE and put an IP address in for the first argument to getaddrinfo().

### connect() - Hey, you!

The `connect()` function is a system call used in socket programming to establish a connection to a remote host(sockaddr contain destination port and IP address).

It is important to note that this function is typically used with sockets of type `SOCK_STREAM`, which provides a reliable, connection-oriented communication channel (e.g., TCP).

```cpp
#include <sys/types.h>
#include <sys/socket.h>
int connect(int sockfd, struct sockaddr *serv_addr, int addrlen);
```

### Differences between bind() and connect()

- `bind()` is used by a server to specify the local address and port to listen on.
- `connect()` is used by a client to initiate a connection to a remote server.
- `bind()` is typically followed by `listen()` on the server side.
- `connect()` is often followed by data transfer operations on the client side.

### listen() - Will somebody please call me?

If you don’t want to connect to a remote host. Say, just for kicks, that you want to wait for incoming connections and handle them in some way.

```cpp
int listen(int sockfd, int backlog);
```

incoming connections are going to wait in this queue until you accept() them, and this is the limit on how many can queue up.

```cpp
getaddrinfo();
socket();
bind();
listen();
/* accept() goes here */
```

### accept()

What’s going to happen is this: someone far far away will try to connect() to your machine on a port that you are listen()ing on. Their connection will be queued up waiting to be accept()ed. You call accept() and you tell it to get the pending connection. It’ll return to you a **brand new socket file descriptor** to use for this single connection! That’s right, suddenly you have two socket file descriptors for the price of one! The original one is still listening for more new connections, and the newly created one is finally ready to send() and recv(). We’re there!

```cpp
#include <sys/types.h>
#include <sys/socket.h>
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

### send() and recv()

These two functions are for communicating over stream sockets or connected datagram sockets

If you want to use regular unconnected datagram sockets, you’ll need to see the section on sendto() and recvfrom(), below.

```cpp
int send(int sockfd, const void *msg, int len, int flags);
```

sample code:

```cpp
char *msg = "Beej was here!";
int len, bytes_sent;
.
.
.
len = strlen(msg);
bytes_sent = send(sockfd, msg, len, 0);
.
.
.
```

```cpp
int recv(int sockfd, void *buf, int len, int flags);
```

The `recv()` function is used to receive data from a connected socket.

The `send()` function is used to send data over a connected socket.

### sendto() and recvfrom()

For datagram sockets that aren’t connected to remote host.

```cpp
int sendto(int sockfd, const void *msg, int len, unsigned int flags,
const struct sockaddr *to, socklen_t tolen);
```

We also need the destination address! 

```cpp
int recvfrom(int sockfd, void *buf, int len, unsigned int flags,
struct sockaddr *from, int *fromlen);
```

<aside>
💡 IF you connect() a datagram socket, you can then simply use send() and recv() for all
your transactions.

</aside>

### close() and shutdown()

```cpp
close(sockfd);
```

This will prevent any more reads and writes to the socket. Anyone attempting to read or write the socket on the remote end will receive an error.

for more control:

<p align="center">
  <img src="https://github.com/duarte3333/IRC/assets/76222459/5ed877b2-b3fb-4ab1-9d8a-54806f099c3f" alt="Image Description" style="width: 70%;">
</p>

```cpp
int shutdown(int sockfd, int how);
```

<aside>
💡 It’s important to note that shutdown() doesn’t actually close the file descriptor—it just changes its us-ability. To free a socket descriptor, you need to use close().

</aside>

### gethostname()

The `gethostname()` function is used to get the standard host name for the current machine.

### getpeername()

The `getpeername()` function is used in socket programming to retrieve the address of the connected peer (the remote host) to which a socket is connected.

### Client-Server Background

<p align="center">
  <img src="https://github.com/duarte3333/IRC/assets/76222459/742e12c2-c7bc-4ec6-ab31-573cf0a41417" alt="Image Description" style="width: 70%;">
</p>

### A simple server

All this server does is send the string “Hello, world!” out over a stream connection. All you need to
do to test this server is run it in one window, and telnet to it from another with:
$ telnet remotehostname 3490

**Server**

```cpp
/*
** server.c -- a stream socket server demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#define PORT "3490"  // the port users will be connecting to

#define BACKLOG 10	 // how many pending connections queue will hold

void sigchld_handler(int s)
{
	(void)s; // quiet unused variable warning

	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(void)
{
	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	printf("server: waiting for connections...\n");

	while(1) {  // main accept() loop
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),
			s, sizeof s);
		printf("server: got connection from %s\n", s);

		if (!fork()) { // this is the child process
			close(sockfd); // child doesn't need the listener
			if (send(new_fd, "Hello, world!", 13, 0) == -1)
				perror("send");
			close(new_fd);
			exit(0);
		}
		close(new_fd);  // parent doesn't need this
	}

	return 0;
}
```

**client**

```cpp
/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#define PORT "3490" // the port client will be connecting to 

#define MAXDATASIZE 100 // max number of bytes we can get at once 

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	int sockfd, numbytes;  
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	if (argc != 2) {
	    fprintf(stderr,"usage: client hostname\n");
	    exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure

	if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
	    perror("recv");
	    exit(1);
	}

	buf[numbytes] = '\0';

	printf("client: received '%s'\n",buf);

	close(sockfd);

	return 0;
}
```

### Blocking

“block” is techie jargon for “sleep”. You probably noticed that when you run listener, above, it just sits there until a packet arrives.

```cpp
#include <unistd.h>
#include <fcntl.h>
.
.
.
sockfd = socket(PF_INET, SOCK_STREAM, 0);
fcntl(sockfd, F_SETFL, O_NONBLOCK);
```

If you try to read from a non-blocking socket and there’s no data there, it’s not allowed to block—it will return -1 and
errno will be set to EAGAIN or EWOULDBLOCK.

### poll()—Synchronous I/O Multiplexing

What you really want to be able to do is somehow monitor a bunch of sockets at once and then handle the ones that have data ready. This way you don’t have to continuously poll all those sockets to see which are ready to read.

In a nutshell, we’re going to ask the operating system to do all the dirty work for us, and just let us know when some data is ready to read on which sockets. In the meantime, our process can go to sleep, saving system resources.

```cpp
#include <poll.h>
int poll(struct pollfd fds[], nfds_t nfds, int timeout);
```

fds is our array of information (which sockets to monitor for what), nfds is the count of elements in the array, and timeout is a timeout in milliseconds. It returns the number of elements in the array that have
had an event occur.

```cpp
struct pollfd {
	int fd; // the socket descriptor
	short events; // bitmap of events we're interested in
	short revents; // when poll() returns, bitmap of events that occurred
};
```

![Untitled](IRC%209b701266ff974dee98a54061c75410ab/Untitled%209.png)

### Select and Poll

`select` and `poll` are both system calls in C and C++ used for handling multiple file descriptors to check for readability, writability, or exceptions. They are commonly used in network programming and asynchronous I/O operations. Here's a brief explanation of each:

### `select`:

`select` is an older system call and is part of the Berkeley sockets API. It allows a program to monitor multiple file descriptors, waiting until one or more of the file descriptors become "ready" for I/O operations. The file descriptors are organized into sets, and `select` can monitor these sets for readability, writability, and exceptions.

Here's a basic usage example:

```cpp
#include <sys/time.h>#include <sys/types.h>#include <unistd.h>#include <stdio.h>int main() {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(STDIN_FILENO, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 seconds timeout
    timeout.tv_usec = 0;

    int ready = select(STDIN_FILENO + 1, &read_fds, NULL, NULL, &timeout);

    if (ready == -1) {
        perror("select");
    } else if (ready) {
        printf("Data is available to read on stdin.\n");
    } else {
        printf("Timeout occurred.\n");
    }

    return 0;
}

```

### `poll`:

`poll` is a more modern alternative to `select` and is part of the POSIX standard. It operates similarly to `select` but provides a more scalable and flexible interface.

Here's a basic example of using `poll`:

```cpp
#include <poll.h>#include <stdio.h>int main() {
    struct pollfd fds[1];
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;

    int ready = poll(fds, 1, 5000);  // 5 seconds timeout

    if (ready == -1) {
        perror("poll");
    } else if (ready) {
        printf("Data is available to read on stdin.\n");
    } else {
        printf("Timeout occurred.\n");
    }

    return 0;
}

```

Both `select` and `poll` are used for similar purposes, but `poll` is generally considered more flexible and efficient, especially when dealing with a large number of file descriptors. However, in some systems or situations, you may still encounter code that uses `select`. Modern programming often favors other mechanisms like `epoll` on Linux or `kqueue` on BSD systems for even better performance in handling large numbers of file descriptors.
# ft_irc

Tutorial Link for Server Build:

https://beej.us/guide/bgnet/pdf/bgnet_a4_c_1.pdf

https://en.wikipedia.org/wiki/List_of_Internet_Relay_Chat_commands

https://www.youtube.com/watch?v=BDV8zK6Y8EU

https://modern.ircdocs.horse

# Concepts

- IRC (Internet Relay Chat):

  IRC is a text-based communication protocol used for real-time chat and messaging.
  It allows users to join channels, send private messages, and participate in group discussions.


- IRC Server:

  An IRC server is a program that manages connections between IRC clients. It facilitates the exchange of messages among clients.

- IRC Client:

  An IRC client is a program or application that connects to an IRC server to send and receive messages. Users interact with the IRC server through the client.

- Socket:

  A socket is a communication endpoint that allows processes on different devices to communicate over a network. It is identified by an IP address and a port number.

- Socket Programming:

  Socket programming involves using sockets to establish communication between processes over a network. In C++, the <sys/socket.h> and <arpa/inet.h> headers are commonly used for socket programming.

- Port:

  A port is a 16-bit unsigned integer that identifies a specific process to which a message is to be delivered on a host. IRC servers typically listen on a specific port (e.g., 6667).

- IP Address:

  An IP (Internet Protocol) address is a numerical label assigned to each device connected to a computer network that uses the Internet Protocol for communication. IPv4 addresses are typically used in IRC (e.g., "192.168.1.1").

- Listening:

  When a server is "listening," it means it's actively waiting for incoming connections from clients.

- Accepting Connections:

  The server uses the accept() system call to accept incoming connection requests from clients.


# Functions

- The socket() function is part of the sockets API and is commonly used for creating a socket, which is a communication endpoint for sending or receiving data over a network. 

- The close(serverSocket) function is used to close the socket when it is no longer needed.

- The setsockopt() function is used in C and C++ to set options on a socket. It allows you to configure various aspects of socket behavior.


- The getsockname() function is used in C and C++ to retrieve the local address to which a socket is bound. It's commonly used on a server-side socket after the socket has been bound to an address using bind.

- The getprotobyname() function is used in C and C++ to retrieve protocol information by specifying its name.

- The gethostbyname() function is a legacy function used in C and C++ to retrieve host information by specifying its name. It's important to note that gethostbyname() is considered deprecated, and its use is discouraged in favor of more modern and robust alternatives, such as getaddrinfo().

- The getaddrinfo() is a more modern and flexible function for resolving hostnames and service names to socket addresses. It is recommended over older functions like gethostbyname() and provides support for both IPv4 and IPv6. Additionally, getaddrinfo() can handle multiple addresses for a given host and supports service name resolution.

- The freeaddrinfo() function is used to free the memory allocated by the getaddrinfo() function when it's used to resolve hostnames and service names to socket addresses. When you call getaddrinfo(), it dynamically allocates memory to store information about the addresses it retrieves. It is your responsibility to release this memory when you are done using the results.


- The bind() function in C and C++ is used to associate a socket with a specific local address and port. This is a crucial step, especially for servers, as it allows them to "bind" to a specific network interface and port on the machine.

- The listen() function in C and C++ is used on a server-side socket to set it in a passive mode, allowing it to accept incoming connections from clients. After calling listen(), the server can use the accept() function to handle incoming connection requests.

- The accept() function in C and C++ is used on a server-side socket to accept an incoming connection from a client. It is typically used in a loop, where the server continuously accepts connections from clients and processes their requests.


- htons() stands for "host to network short." It is a function used in C and C++ programming, especially in network programming, to convert a 16-bit quantity (e.g., a port number) from host byte order to network byte order.
    Different computer architectures have different byte orders (endianness). Network protocols, however, typically use a standardized byte order called network byte order, which is big-endian. The htons function ensures that a 16-bit quantity is represented in the byte order expected by network protocols.

- htonl() stands for "host to network long." It is a function used in C and C++ programming, particularly in network programming, to convert a 32-bit quantity (e.g., an IPv4 address or a 32-bit integer) from host byte order to network byte order. As with htons() for 16-bit quantities, htonl() ensures that a 32-bit quantity is represented in the byte order expected by network protocols, which is big-endian.

- ntohs() stands for "network to host short." It is a function used in C and C++ programming, especially in network programming, to convert a 16-bit quantity (e.g., a port number) from network byte order to host byte order.
    Different computer architectures have different byte orders (endianness), and network protocols typically use a standardized byte order called network byte order, which is big-endian. The ntohs function ensures that a 16-bit quantity received from the network is correctly interpreted on a host with its native byte order.

- ntohl() stands for "network to host long." It is a function used in C and C++ programming, particularly in network programming, to convert a 32-bit quantity (e.g., an IPv4 address or a 32-bit integer) from network byte order to host byte order. Just like ntohs for 16-bit quantities, ntohl ensures that a 32-bit quantity received from the network is correctly interpreted on a host with its native byte order.


- inet_addr() is a function in C and C++ that converts an IPv4 address in dot-decimal notation (e.g., "192.168.1.1") into its binary representation as a 32-bit unsigned integer in network byte order.

- inet_ntoa is a function in C and C++ that converts a 32-bit IPv4 address in network byte order to a string in dot-decimal notation. Dot-decimal notation represents the IPv4 address as four decimal numbers separated by dots (e.g., "192.168.1.1").


- The send() function is used in C and C++ for sending data over a connected socket. It's commonly used in network programming to transmit data from one end of a connection (usually a socket) to the other.

- The recv() function is used in C and C++ for receiving data from a connected socket. It's commonly used in network programming to retrieve data sent from the other end of a connection, such as a server receiving data from a client.


- The signal() function is part of the C and C++ standard libraries and is used to handle signals in a program. Signals are a form of inter-process communication used by operating systems to notify processes about specific events or conditions. Common signals include things like SIGINT (sent when the user presses Ctrl+C) and SIGSEGV (sent when a segmentation fault occurs).

- sigaction() is a function used in C and C++ for more advanced and reliable signal handling compared to the older signal function. The sigaction function allows for more fine-grained control over how signals are handled, including specifying additional options and behaviors.


- lseek() is a system call in Unix-like operating systems that is used to change the file offset associated with a given file descriptor. The file offset is essentially the position in the file where the next read or write operation will occur. lseek is part of the standard I/O library in C.

- The fstat function is a system call in Unix-like operating systems that retrieves information about an open file descriptor, such as its size, permissions, and other attributes. It is often used to obtain information about a file before performing certain operations.

- The fcntl() (file control) function is a system call in Unix-like operating systems that is used for various operations on open file descriptors. It provides a way to modify or obtain information about file descriptor properties, such as file status flags and file locks.

- The poll() function is a system call in Unix-like operating systems that is used for monitoring multiple file descriptors to see if they are ready for I/O operations. It is often used as an alternative to the older select system call and provides similar functionality.













# ft_irc

Tutorial Link for Server Build:

https://beej.us/guide/bgnet/pdf/bgnet_a4_c_1.pdf

https://en.wikipedia.org/wiki/List_of_Internet_Relay_Chat_commands

https://www.youtube.com/watch?v=BDV8zK6Y8EU

https://modern.ircdocs.horse

# Concepts

- IRC (Internet Relay Chat):

  IRC is a text-based communication protocol used for real-time chat and messaging.
  It allows users to join channels, send private messages, and participate in group discussions.


- IRC Server:

  An IRC server is a program that manages connections between IRC clients. It facilitates the exchange of messages among clients.

- IRC Client:

  An IRC client is a program or application that connects to an IRC server to send and receive messages. Users interact with the IRC server through the client.

- Socket:

  A socket is a communication endpoint that allows processes on different devices to communicate over a network. It is identified by an IP address and a port number.

- Socket Programming:

  Socket programming involves using sockets to establish communication between processes over a network. In C++, the <sys/socket.h> and <arpa/inet.h> headers are commonly used for socket programming.

- Port:

  A port is a 16-bit unsigned integer that identifies a specific process to which a message is to be delivered on a host. IRC servers typically listen on a specific port (e.g., 6667).

- IP Address:

  An IP (Internet Protocol) address is a numerical label assigned to each device connected to a computer network that uses the Internet Protocol for communication. IPv4 addresses are typically used in IRC (e.g., "192.168.1.1").

- Listening:

  When a server is "listening," it means it's actively waiting for incoming connections from clients.

- Accepting Connections:

  The server uses the accept() system call to accept incoming connection requests from clients.


# Functions

- The socket() function is part of the sockets API and is commonly used for creating a socket, which is a communication endpoint for sending or receiving data over a network. 

- The close(serverSocket) function is used to close the socket when it is no longer needed.

- The setsockopt() function is used in C and C++ to set options on a socket. It allows you to configure various aspects of socket behavior.


- The getsockname() function is used in C and C++ to retrieve the local address to which a socket is bound. It's commonly used on a server-side socket after the socket has been bound to an address using bind.

- The getprotobyname() function is used in C and C++ to retrieve protocol information by specifying its name.

- The gethostbyname() function is a legacy function used in C and C++ to retrieve host information by specifying its name. It's important to note that gethostbyname() is considered deprecated, and its use is discouraged in favor of more modern and robust alternatives, such as getaddrinfo().

- The getaddrinfo() is a more modern and flexible function for resolving hostnames and service names to socket addresses. It is recommended over older functions like gethostbyname() and provides support for both IPv4 and IPv6. Additionally, getaddrinfo() can handle multiple addresses for a given host and supports service name resolution.

- The freeaddrinfo() function is used to free the memory allocated by the getaddrinfo() function when it's used to resolve hostnames and service names to socket addresses. When you call getaddrinfo(), it dynamically allocates memory to store information about the addresses it retrieves. It is your responsibility to release this memory when you are done using the results.


- The bind() function in C and C++ is used to associate a socket with a specific local address and port. This is a crucial step, especially for servers, as it allows them to "bind" to a specific network interface and port on the machine.

- The listen() function in C and C++ is used on a server-side socket to set it in a passive mode, allowing it to accept incoming connections from clients. After calling listen(), the server can use the accept() function to handle incoming connection requests.

- The accept() function in C and C++ is used on a server-side socket to accept an incoming connection from a client. It is typically used in a loop, where the server continuously accepts connections from clients and processes their requests.


- htons() stands for "host to network short." It is a function used in C and C++ programming, especially in network programming, to convert a 16-bit quantity (e.g., a port number) from host byte order to network byte order.
    Different computer architectures have different byte orders (endianness). Network protocols, however, typically use a standardized byte order called network byte order, which is big-endian. The htons function ensures that a 16-bit quantity is represented in the byte order expected by network protocols.

- htonl() stands for "host to network long." It is a function used in C and C++ programming, particularly in network programming, to convert a 32-bit quantity (e.g., an IPv4 address or a 32-bit integer) from host byte order to network byte order. As with htons() for 16-bit quantities, htonl() ensures that a 32-bit quantity is represented in the byte order expected by network protocols, which is big-endian.

- ntohs() stands for "network to host short." It is a function used in C and C++ programming, especially in network programming, to convert a 16-bit quantity (e.g., a port number) from network byte order to host byte order.
    Different computer architectures have different byte orders (endianness), and network protocols typically use a standardized byte order called network byte order, which is big-endian. The ntohs function ensures that a 16-bit quantity received from the network is correctly interpreted on a host with its native byte order.

- ntohl() stands for "network to host long." It is a function used in C and C++ programming, particularly in network programming, to convert a 32-bit quantity (e.g., an IPv4 address or a 32-bit integer) from network byte order to host byte order. Just like ntohs for 16-bit quantities, ntohl ensures that a 32-bit quantity received from the network is correctly interpreted on a host with its native byte order.


- inet_addr() is a function in C and C++ that converts an IPv4 address in dot-decimal notation (e.g., "192.168.1.1") into its binary representation as a 32-bit unsigned integer in network byte order.

- inet_ntoa is a function in C and C++ that converts a 32-bit IPv4 address in network byte order to a string in dot-decimal notation. Dot-decimal notation represents the IPv4 address as four decimal numbers separated by dots (e.g., "192.168.1.1").


- The send() function is used in C and C++ for sending data over a connected socket. It's commonly used in network programming to transmit data from one end of a connection (usually a socket) to the other.

- The recv() function is used in C and C++ for receiving data from a connected socket. It's commonly used in network programming to retrieve data sent from the other end of a connection, such as a server receiving data from a client.


- The signal() function is part of the C and C++ standard libraries and is used to handle signals in a program. Signals are a form of inter-process communication used by operating systems to notify processes about specific events or conditions. Common signals include things like SIGINT (sent when the user presses Ctrl+C) and SIGSEGV (sent when a segmentation fault occurs).

- sigaction() is a function used in C and C++ for more advanced and reliable signal handling compared to the older signal function. The sigaction function allows for more fine-grained control over how signals are handled, including specifying additional options and behaviors.


- lseek() is a system call in Unix-like operating systems that is used to change the file offset associated with a given file descriptor. The file offset is essentially the position in the file where the next read or write operation will occur. lseek is part of the standard I/O library in C.

- The fstat function is a system call in Unix-like operating systems that retrieves information about an open file descriptor, such as its size, permissions, and other attributes. It is often used to obtain information about a file before performing certain operations.

- The fcntl() (file control) function is a system call in Unix-like operating systems that is used for various operations on open file descriptors. It provides a way to modify or obtain information about file descriptor properties, such as file status flags and file locks.

- The poll() function is a system call in Unix-like operating systems that is used for monitoring multiple file descriptors to see if they are ready for I/O operations. It is often used as an alternative to the older select system call and provides similar functionality.

