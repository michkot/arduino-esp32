#pragma once

class WiFiSocketWrapper {
private:

public:
    const int sockfd;
    
    WiFiSocketWrapper(int fd);
    ~WiFiSocketWrapper();
    int fd();
};
