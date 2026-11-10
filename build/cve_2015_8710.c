#include <string.h>
#include <stdio.h>
#include <libxml/HTMLparser.h>
int main(int argc, char** argv){
    FILE*f=fopen(argv[1],"rb"); char b[256]; size_t n=fread(b,1,255,f); b[n]=0; fclose(f);
    int opt=HTML_PARSE_RECOVER|HTML_PARSE_NOERROR|HTML_PARSE_NOWARNING|HTML_PARSE_NONET;
    xmlDocPtr doc=htmlReadMemory(b,strlen(b),NULL,"UTF-8",opt);
    if(doc) xmlFreeDoc(doc);
    printf("done\n"); return 0;
}
