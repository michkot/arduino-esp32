#pragma once

class WiFiSocketWrapper {
private:
    int sockfd;

public:
    WiFiSocketWrapper(int fd);
    ~WiFiSocketWrapper();
    int fd();
};
