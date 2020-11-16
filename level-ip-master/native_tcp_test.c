#include "include/syshead.h"
#include <sys/time.h>

#define MAX_CMD_LENGTH 6
#define SND_BUF_SIZE 8192
#define RCV_BUF_SIZE 87300
#define MSG_SIZE 1000

#define NUM_BYTES_TO_SEND 100000000


void tcp_client(int server_port) {

  int clientSocket;
  int sndBufSize = SND_BUF_SIZE;
  int rcvBufSize = RCV_BUF_SIZE;
  char buffer[1024];
  struct sockaddr_in serverAddr;
  socklen_t addr_size;

  printf ("Client: MyPid: %d\n", getpid());

  clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  printf ("Client socket fd = %d\n", clientSocket);

  if (sndBufSize > 0)
  setsockopt(clientSocket, SOL_SOCKET, SO_SNDBUF, &sndBufSize, sizeof(sndBufSize));

  if (rcvBufSize > 0)
  setsockopt(clientSocket, SOL_SOCKET, SO_RCVBUF, &rcvBufSize, sizeof(rcvBufSize));
  
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(server_port);
  serverAddr.sin_addr.s_addr = inet_addr("10.0.0.254");
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

  usleep(1000000);
  addr_size = sizeof serverAddr;
  printf ("Connecting to server ...\n");
  connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);
  printf ("Waiting for data ...\n");

  int numReceived = 0;

  struct timeval start, stop;
  gettimeofday(&start, NULL);
  while (numReceived < NUM_BYTES_TO_SEND) {
    int ret = read(clientSocket, buffer, 1024);
    if (ret < 0)
      break;
    numReceived += ret;
  }
  gettimeofday(&stop, NULL);
  double time_taken = ((double)stop.tv_sec + (double)stop.tv_usec / 1e6 - ((double)start.tv_sec  + (double)start.tv_usec / 1e6)); 
  
  printf ("Received msg: %s, len = %ld\n", buffer, strlen(buffer));
  printf ("Time taken: %f (secs)\n", time_taken);
  printf ("Rcv Throughput (MBps) : %f\n", NUM_BYTES_TO_SEND/(1e6 * time_taken));


  printf ("Closing client socket !\n");
  close(clientSocket);   
}

void tcp_server(int server_port) {

  int welcomeSocket, newSocket;
  char buffer[1024];
  struct sockaddr_in serverAddr;
  struct sockaddr_storage serverStorage;
  int sndBufSize = SND_BUF_SIZE;
  int rcvBufSize = RCV_BUF_SIZE;
  int ret;
 
  welcomeSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  printf ("Server: MyPid: %d\n", getpid());
  printf ("Welcome socket fd = %d\n", welcomeSocket);

  if (sndBufSize > 0)
  setsockopt(welcomeSocket, SOL_SOCKET, SO_SNDBUF, &sndBufSize, sizeof(sndBufSize));

  if (rcvBufSize > 0)
  setsockopt(welcomeSocket, SOL_SOCKET, SO_RCVBUF, &rcvBufSize, sizeof(rcvBufSize));

  
  
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(server_port);
  serverAddr.sin_addr.s_addr = inet_addr("10.0.0.254");

  int addrLen = sizeof (struct sockaddr);
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

  printf ("Binding to server addr ...\n");
  bind(welcomeSocket, (struct sockaddr *) &serverAddr, sizeof (struct sockaddr));

  printf ("Listening for new connections ...\n");
  if(listen(welcomeSocket, 5)==0)
    printf("Listening\n");
  else
    printf("Error\n");

  printf ("Accepting new connections ...\n");
  newSocket = accept(welcomeSocket, (struct sockaddr *) &serverStorage, (socklen_t *)&addrLen);

  if (sndBufSize > 0)
  ret = setsockopt(newSocket, SOL_SOCKET, SO_SNDBUF, &sndBufSize, sizeof(sndBufSize));

  if (ret < 0) {
    printf ("newSock: SO_SNDBUF Error: %d\n", ret);
  }

  if (rcvBufSize > 0)
  ret = setsockopt(newSocket, SOL_SOCKET, SO_RCVBUF, &rcvBufSize, sizeof(rcvBufSize));

  if (ret < 0) {
    printf ("newSock: SO_RCVBUF Error: %d\n", ret);
  }

  printf ("New Socket fd = %d\n", newSocket);
  memset(buffer, 0, 1024);
  for (int i = 0; i < MSG_SIZE; i++) {
    buffer[i] = 'a';
  }

  int msgLength = MSG_SIZE;
  int numSent = 0;

  printf ("Msg-length: %d, Sending msgs to client ...\n", msgLength);
  struct timeval start, stop;
  int numChkPt = 0;
  gettimeofday(&start, NULL);

  while (numSent < NUM_BYTES_TO_SEND) {
    write(newSocket,buffer,msgLength);
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
  printf ("Send Throughput (MBps) : %f\n", NUM_BYTES_TO_SEND/(1e6 *time_taken));


  printf ("Closing New Socket \n");
  close(newSocket);

  printf ("Closing Welcome Socket \n");
  close(welcomeSocket);

  printf ("Finished server ...\n");
}



int main(int argc, char** argv) {
    
    
    if (argc < 3) {
        printf ("Not enough args: ./natve-tcp [client or server] server_port\n");
        exit(0);
    }

    if (strcmp(argv[1], "client") == 0) {
        tcp_client(atoi(argv[2]));
    } else {
        tcp_server(atoi(argv[2]));
    }
}
