#include "syshead.h"
#include "basic.h"
#include "utils.h"
#include "timer.h"
#include "tcp.h"
#include "netdev.h"
#include "socket.h"
#include "ip.h"
#include <sys/time.h>

#define MAX_CMD_LENGTH 6
#define SND_BUF_SIZE 16384
#define RCV_BUF_SIZE 131072
#define MSG_SIZE 1000

#define NUM_BYTES_TO_SEND 100000000
//#define NUM_BYTES_TO_SEND 13

typedef void (*sighandler_t)(int);

#define THREAD_CORE 0
#define THREAD_TIMERS 1
static pthread_t threads[2];

int running;

static void create_thread(pthread_t id, void *(*func) (void *)) {
    if (pthread_create(&threads[id], NULL,
                       func, NULL) != 0) {
        print_err("Could not create core thread\n");
    }
}

static void init_stack(uint32_t src_ip_addr) {
    netdev_init(src_ip_addr);
}

static void run_threads() {
    create_thread(THREAD_CORE, netdev_rx_loop);
    create_thread(THREAD_TIMERS, timers_start);
}

static void wait_for_threads() {
    for (int i = 0; i < 2; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            print_err("Error when joining threads\n");
            exit(1);
        }
    }
}

void free_stack() {
    printf ("Cleaning up TCP stack ! ...\n");
    abort_sockets();
}



void tcp_client(int server_port) {

  int clientSocket;
  int sndBufSize = SND_BUF_SIZE;
  int rcvBufSize = RCV_BUF_SIZE;
  char buffer[1024];
  struct sockaddr_in serverAddr;
  socklen_t addr_size;

  printf ("Client: MyPid: %d\n", getpid());

  clientSocket = _socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  printf ("Client socket fd = %d\n", clientSocket);

  if (sndBufSize > 0)
  _setsockopt(clientSocket, SOL_SOCKET, SO_SNDBUF, &sndBufSize, sizeof(sndBufSize));

  if (rcvBufSize > 0)
  _setsockopt(clientSocket, SOL_SOCKET, SO_RCVBUF, &rcvBufSize, sizeof(rcvBufSize));
  
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(server_port);
  serverAddr.sin_addr.s_addr = inet_addr("10.0.0.254");
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

  usleep(1000000);
  addr_size = sizeof serverAddr;
  printf ("Connecting to server ...\n");
  _connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);
  printf ("Waiting for data ...\n");

  int numReceived = 0;

  struct timeval start, stop;
  gettimeofday(&start, NULL);
  while (numReceived < NUM_BYTES_TO_SEND) {
    int ret = _read(clientSocket, buffer, 1024);
    if (ret < 0)
      break;
    numReceived += ret;
  }
  gettimeofday(&stop, NULL);
  double time_taken = ((double)stop.tv_sec + (double)stop.tv_usec / 1e6 - ((double)start.tv_sec  + (double)start.tv_usec / 1e6)); 
  
  printf ("Received msg: %s\n", buffer);
  printf ("Time taken: %f (secs)\n", time_taken);
  printf ("Rcv Throughput (MBps) : %f\n", NUM_BYTES_TO_SEND/(1e6 *time_taken));

  /*const char * reply = "Echo Reply: Hello World!";

  if (ret > 0) {
    printf("Received: %d bytes, Data received: %s", ret, buffer);
    _write(clientSocket, reply, strlen(reply));
  } else
    printf ("Data read ret = %d\n", ret);*/

  printf ("Closing client socket !\n");
  _close(clientSocket);   
}
void tcp_server(int server_port) {

  int welcomeSocket, newSocket;
  char buffer[1024];
  struct sockaddr_in serverAddr;
  struct sockaddr_storage serverStorage;
  //int ret;
  int sndBufSize = SND_BUF_SIZE;
  int rcvBufSize = RCV_BUF_SIZE;
  //char * finishMsg = "DONE";

  welcomeSocket = _socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  printf ("Server: MyPid: %d\n", getpid());
  printf ("Welcome socket fd = %d\n", welcomeSocket);

  if (sndBufSize > 0)
  _setsockopt(welcomeSocket, SOL_SOCKET, SO_SNDBUF, &sndBufSize, sizeof(sndBufSize));

  if (rcvBufSize > 0)
  _setsockopt(welcomeSocket, SOL_SOCKET, SO_RCVBUF, &rcvBufSize, sizeof(rcvBufSize));

  
  
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(server_port);
  serverAddr.sin_addr.s_addr = inet_addr("10.0.0.254");
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

  printf ("Binding to server addr ...\n");
  _bind(welcomeSocket, (struct sockaddr *) &serverAddr);

  printf ("Listening for new connections ...\n");
  if(_listen(welcomeSocket, 5)==0)
    printf("Listening\n");
  else
    printf("Error\n");

  printf ("Accepting new connections ...\n");
  newSocket = _accept(welcomeSocket, (struct sockaddr *) &serverStorage);
  printf ("New Socket fd = %d\n", newSocket);
  memset(buffer, 0, 1024);
  for (int i = 0; i < MSG_SIZE; i++) {
    buffer[i] = 'a';
  }

  int msgLength = strlen(buffer);
  int numSent = 0;

  printf ("Sending msgs to client ...\n");
  struct timeval start, stop;
  int numChkPt = 0;
  gettimeofday(&start, NULL);

  while (numSent < NUM_BYTES_TO_SEND) {
    _write(newSocket,buffer,msgLength);
    numSent += msgLength;
    numChkPt += msgLength;
    if (numChkPt > 1000000) {
      printf ("Sent: %d bytes\n", numSent);
      numChkPt = 0;
    }
  }
  
  gettimeofday(&stop, NULL);
  double time_taken = ((double)stop.tv_sec + (double)stop.tv_usec / 1e6 - ((double)start.tv_sec  + (double)start.tv_usec / 1e6)); 
  printf ("Time taken: %f (secs)\n", time_taken);
  printf ("Send Throughput (MBps) : %f\n", NUM_BYTES_TO_SEND/(1e6*time_taken));


  /*memset(buffer, 0, 1024);
  ret = _read(newSocket, buffer, 1024);
  printf ("Received: %d bytes: %s\n", ret, buffer);*/

  printf ("Closing New Socket \n");
  _close(newSocket);

  printf ("Closing Welcome Socket \n");
  _close(welcomeSocket);

  printf ("Finished server ...\n");
}



int main(int argc, char** argv) {
    
    
    if (argc < 4) {
        printf ("Not enough args: ./stack [client or server] ip server_port\n");
        exit(0);
    }

    running = 1;

    init_stack(inet_addr(argv[2]));  
    run_threads();

    if (strcmp(argv[1], "client") == 0) {
        tcp_client(atoi(argv[3]));
    } else {
        tcp_server(atoi(argv[3]));
    }

    running = 0;
    wait_for_threads();
    free_stack();
}
