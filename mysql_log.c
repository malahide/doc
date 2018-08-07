//Ver 0.1
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#ifndef WIN32
#  include <unistd.h>
#else
#  include <process.h>
#  define snprintf sprintf_s
#endif

#include <mosquitto.h>
//#include <mysql/mysql.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <openssl/aes.h>

#define SKT_mqtt_host "thingplugpf.sktiot.com"
#define SKT_mqtt_port 8883
//#define SKT_mqtt_ClientID "00000003702c1ffffe1f2f96"
#define SKT_mqtt_ClientID "ktw1525@kesco.or.kr_0002"
#define SKT_mqtt_User_Nm "ktw1525@kesco.or.kr"
#define SKT_mqtt_User_PW "b1JPMytzdzlpVWtlUm5jWUNhMUl3bDlNRG5VOGZsWUhkc01tNkhnajVqQXBLNlpFd1BLK1JJMk1ueGNNVGh2UA=="
//#define SKT_mqtt_SubTopic "/oneM2M/req/0000000000000003/00000003702c1ffffe1b5a29"
#define SKT_mqtt_SubTopic "/oneM2M/req_msg/e0610004a0000000/ktw1525@kesco.or.kr_0002"
//#define Mycafile "/etc/pki/tls/certs/ca-bundle.crt" //Redhat and CentOS
#define Mycafile "/etc/ssl/certs/ca-certificates.crt" //ubuntu


//#define KESCO_mqtt_host "localhost"
#define KESCO_mqtt_host "192.168.43.31"
#define KESCO_mqtt_port 1883
#define KESCO_mqtt_PubTopic "/SGBEL/lab/ictcenter/e0610004a0000000"

//#define SGBEL MQ
#define SGBEL_mqtt_host "115.90.42.34"
#define SGBEL_mqtt_port 31704
#define SGBEL_mqtt_PubTopic "/SGBEL/lab/ictcenter/e0610004a0000000"

static int run = 1; //SIGNAL process

struct mosquitto *KESCO_mosq;
struct mosquitto *SGBEL_mosq;

int hex_to_int(char c){
    int first = c / 16 - 3;
    int second = c % 16;
    int result = first*10 + second;
    if(result > 9) result--;
    return result;
}

int hexstr_to_ascii(xmlChar *key, char *rtn){
    
    int high, low;
    
    int length = 0;
    int i;
    char testbuf = 0;
    char testbuf1[] = "0";
    
    memset(rtn, 0, 512*sizeof(char));
    
    length = strlen((char*)key);
    
    for(i = 0; i < length; i++){
        if(i % 2 != 0){
            high = hex_to_int(testbuf) * 16;
            low = hex_to_int(key[i]);
            testbuf1[0] = (char)(high+low);
            strcat(rtn,testbuf1);
        }else{
            testbuf = key[i];
        }
    }
    return 0;
}

static void parseDoc(char *buf, char *devID, char *ct, char *con) {
    xmlDocPtr doc;
    xmlNodePtr cur;
    xmlChar *xmlbuf;
    
    xmlbuf = (xmlChar *)buf;
    doc = xmlParseDoc(xmlbuf);
    
    xmlChar *key;
    
    if(doc == NULL) {
        fprintf(stderr, "Document not parsed successfully.\n");
        return;
    }
    cur = xmlDocGetRootElement(doc);
    if(cur == NULL) {
        fprintf(stderr, "empty document\n");
        xmlFreeDoc(doc);
        return;
    }
    if(xmlStrcmp(cur->name, (const xmlChar *)"req")) {
        fprintf(stderr, "document of the wrong type, root node != req\n");
        xmlFreeDoc(doc);
        return;
    }
    
    cur = cur->xmlChildrenNode;
    while(cur != NULL) {
        if((!xmlStrcmp(cur->name, (const xmlChar *)"fr"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            //printf("DevID           : %s\n", key);
            sprintf(devID, "%s",key);
        }
        
        if((!xmlStrcmp(cur->name, (const xmlChar *)"pc"))) {
            break;
        }
        
        cur = cur->next;
    }

    cur = cur->xmlChildrenNode;

    while(cur != NULL) {
        if((!xmlStrcmp(cur->name, (const xmlChar *)"cin"))) {
            break;
        }
        
        //mgmt Cmd retrun sub XML
        if((!xmlStrcmp(cur->name, (const xmlChar *)"exin"))) {
            break;
        }
        
        cur = cur->next;
    }

    cur = cur->xmlChildrenNode;
    while(cur != NULL) {
        if((!xmlStrcmp(cur->name, (const xmlChar *)"ct"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            //printf("Data Create Time: %s\n", key);
            sprintf(ct, "%s",key);
        }
        
        if((!xmlStrcmp(cur->name, (const xmlChar *)"con"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            //printf("Dev Value       : %s\n", key);
            hexstr_to_ascii(key,con);

        }

        //mgmt Cmd retrun sub XML
        if((!xmlStrcmp(cur->name, (const xmlChar *)"ext"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            //printf("mgmt Cmd retrun ext: %s\n", key);
            //sprintf(ct, "%s",key);
        }
        
        cur = cur->next;
    }
    
    
    
    xmlFree(key);
    xmlFreeDoc(doc);
    return;
}

void handle_signal(int s)
{
	run = 0;
}

void connect_callback(struct mosquitto *mosq, void *obj, int result)
{
    printf("SKT broker Connected.\n");
    syslog(LOG_INFO | LOG_LOCAL0, "SKT ThingPlug Connected");
}


void KESCO_connect_callback(struct mosquitto *KESCO_mosq, void *obj, int result)
{
    printf("KESCO broker Connected.\n");
    syslog(LOG_INFO | LOG_LOCAL0, "KESCO broker Connected");
}

void SGBEL_connect_callback(struct mosquitto *SGBEL_mosq, void *obj, int result)
{
    printf("SGBEL broker Connected.\n");
    syslog(LOG_INFO | LOG_LOCAL0, "SGBEL broker Connected");
}


void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    
    char buf[2048];
    memset(buf, 0, 2047*sizeof(char));
    memcpy(buf, message->payload, 2047*sizeof(char));
    
    char devID[24];
    char ct[25];
    char con[512];
    char Topic[1024];
    
    memset(Topic,0,1024*sizeof(char));
    
    printf("payload=>\n[%s]",buf);
    parseDoc(buf,devID, ct, con);
    
    strcat(Topic,devID);
    strcat(Topic,"@");
    strcat(Topic,ct);
    strcat(Topic,"@");
    strcat(Topic,con);
    
    mosquitto_publish(KESCO_mosq, NULL, KESCO_mqtt_PubTopic, strlen(Topic), Topic, 0, true);
	mosquitto_publish(SGBEL_mosq, NULL, SGBEL_mqtt_PubTopic, strlen(Topic), Topic, 0, true);

}

int main(int argc, char *argv[])
{

    syslog(LOG_INFO | LOG_LOCAL0, "Starting Kesco_subpub.");
	char clientid[24];
	struct mosquitto *mosq;
	int rc = 0;
    int rc_1 = 0;
	int rc_2 = 0;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	mosquitto_lib_init();

    memset(clientid, 0, 24);
    //snprintf(clientid, 23, "mysql_log_%d", getpid());
    mosq = mosquitto_new(SKT_mqtt_ClientID, true, NULL);
    if(mosq){
        mosquitto_connect_callback_set(mosq, connect_callback);
        mosquitto_message_callback_set(mosq, message_callback);
        //SKT MQTT set
        mosquitto_username_pw_set(mosq, SKT_mqtt_User_Nm, SKT_mqtt_User_PW);
        mosquitto_tls_set(mosq, Mycafile, NULL, NULL, NULL, NULL);
        //SKT Broker Connect
        rc = mosquitto_connect(mosq, SKT_mqtt_host, SKT_mqtt_port, 60);
        mosquitto_subscribe(mosq, NULL, SKT_mqtt_SubTopic, 0);
              
        KESCO_mosq = mosquitto_new(NULL, true, NULL);
		SGBEL_mosq = mosquitto_new(NULL, true, NULL);
		
		//KESCO broker connect
        if(KESCO_mosq){
            mosquitto_connect_callback_set(KESCO_mosq, KESCO_connect_callback);
            rc_1 = mosquitto_connect(KESCO_mosq, KESCO_mqtt_host, KESCO_mqtt_port, 60);        
        }//end if
		
		//SGBEL broker connect
        if(SGBEL_mosq){
            mosquitto_connect_callback_set(SGBEL_mosq, SGBEL_connect_callback);
            rc_2 = mosquitto_connect(SGBEL_mosq, SGBEL_mqtt_host, SGBEL_mqtt_port, 60);        
        }//end if		

        while(run){
            rc = mosquitto_loop(mosq, -1, 1);
            rc_1 = mosquitto_loop(KESCO_mosq, -1, 1);
			rc_2 = mosquitto_loop(SGBEL_mosq, -1, 1);

            if(run && rc){
                sleep(3);
                mosquitto_reconnect(mosq);
                mosquitto_subscribe(mosq, NULL, SKT_mqtt_SubTopic, 0);
                printf("reconnect ThingPlug\n");
                printf("Error Code: %d %s\n", rc, mosquitto_strerror(rc));
                syslog(LOG_INFO | LOG_LOCAL0, "reconnect ThingPlug");
            }
            
            if(run && rc_1){
                sleep(3);
                mosquitto_reconnect(KESCO_mosq);
                printf("reconnect KESCO\n");
                printf("Error Code: %d %s\n", rc_1, mosquitto_strerror(rc_1));
                syslog(LOG_INFO | LOG_LOCAL0, "reconnect KESCO");
            }
			
            if(run && rc_2){
                sleep(3);
                mosquitto_reconnect(SGBEL_mosq);
                printf("reconnect SGBEL\n");
                printf("Error Code: %d %s\n", rc_2, mosquitto_strerror(rc_2));
                syslog(LOG_INFO | LOG_LOCAL0, "reconnect SGBEL");
            }			
            
        }
        mosquitto_destroy(mosq);
        mosquitto_destroy(KESCO_mosq);
		mosquitto_destroy(SGBEL_mosq);
    
        
    }//end if

	mosquitto_lib_cleanup();

	return rc;
}

