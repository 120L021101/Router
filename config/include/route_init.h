// route_init.h
#ifndef ROUTE_INIT_H
#define ROUTE_INIT_H

#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <cjson/cJSON.h>
#include <arpa/inet.h>  
#include "ipv4_table.h"
  

void config_ipv4_table(IPv4RoutingTable *ipv4RouteTable, const char *filename);

#endif // ROUTE_INIT_H