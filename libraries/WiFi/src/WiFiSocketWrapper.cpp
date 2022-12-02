
#include "WiFiSocketWrapper.h"

#include <lwip/sockets.h>

WiFiSocketWrapper::WiFiSocketWrapper(int fd):sockfd(fd)
{
}

WiFiSocketWrapper::~WiFiSocketWrapper()
{
    close(sockfd);
}

int WiFiSocketWrapper::fd()
{
    return sockfd;
}