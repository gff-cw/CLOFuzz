#include "mms_client_connection.h"
#include "mms_value.h"
#include <stdio.h>
int main(void) {
 MmsError e; MmsConnection c=MmsConnection_create();
 if (!MmsConnection_connect(c,&e,"127.0.0.1",18103)) return 1;
 printf("connect=%d\n",e);
 LinkedList names=MmsConnection_getDomainNames(c,&e); printf("names=%d\n",e);
 if(names) LinkedList_destroy(names);
 MmsValue* v=MmsConnection_readVariable(c,&e,"simpleIOGenericIO","GGIO1$DC$NamPlt$vendor"); printf("read=%d\n",e); if(v) MmsValue_delete(v);
 v=MmsValue_newVisibleString("audit");
 MmsConnection_writeVariable(c,&e,"simpleIOGenericIO","GGIO1$DC$NamPlt$vendor",v); printf("write=%d\n",e); MmsValue_delete(v);
 MmsConnection_conclude(c,&e); printf("conclude=%d\n",e);
 MmsConnection_destroy(c); return 0;
}
