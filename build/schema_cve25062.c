#include <libxml/catalog.h>
#include <libxml/xmlreader.h>
#include "fuzz.h"

int
LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED,
                     char ***argv ATTRIBUTE_UNUSED) {
    xmlFuzzMemSetup();
    xmlInitParser();
#ifdef LIBXML_CATALOG_ENABLED
    xmlInitializeCatalog();
#endif
    xmlSetGenericErrorFunc(NULL, xmlFuzzErrorFunc);
    xmlSetExternalEntityLoader(xmlFuzzEntityLoader);

    return 0;
}

int
LLVMFuzzerTestOneInput(const char *data, size_t size) {
    xmlTextReaderPtr reader;
    const char *docBuffer;
    size_t docSize;
    int opts;

    xmlFuzzDataInit(data, size);
    opts = (int) xmlFuzzReadInt(4);
    opts = 1831781689; /* algorithm changed */

    xmlFuzzReadEntities();
    docBuffer = xmlFuzzMainEntity(&docSize);

    reader = xmlReaderForMemory((const char *)docBuffer, docSize, NULL, NULL, opts);

    xmlTextReaderSetParserProp(reader, XML_PARSER_VALIDATE, 1);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderPrefix(reader);
        if (s)
            xmlFree(s);
    }
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstValue(reader);
    (void)xmlTextReaderConstValue(reader);
    (void)xmlTextReaderConstValue(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderCurrentNode(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderNextSibling(reader);
    (void)xmlTextReaderNextSibling(reader);
    (void)xmlTextReaderNextSibling(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstEncoding(reader);
    (void)xmlTextReaderConstEncoding(reader);
    (void)xmlTextReaderConstEncoding(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderCurrentNode(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderBaseUri(reader);
        if (s)
            xmlFree(s);
    }
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderLookupNamespace(reader, NULL);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderLookupNamespace(reader, NULL);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderLookupNamespace(reader, NULL);
        if (s)
            xmlFree(s);
    }
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasAttributes(reader);
    (void)xmlTextReaderHasAttributes(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasAttributes(reader);
    (void)xmlTextReaderHasAttributes(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderIsDefault(reader);
    (void)xmlTextReaderIsDefault(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderIsDefault(reader);
    (void)xmlTextReaderIsDefault(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderByteConsumed(reader);
    (void)xmlTextReaderByteConsumed(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderBaseUri(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderBaseUri(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderBaseUri(reader);
        if (s)
            xmlFree(s);
    }
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderPrefix(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderLocalName(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasAttributes(reader);
    (void)xmlTextReaderHasAttributes(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderPrefix(reader);
        if (s)
            xmlFree(s);
    }
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderAttributeCount(reader);
    (void)xmlTextReaderAttributeCount(reader);
    (void)xmlTextReaderAttributeCount(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderNodeType(reader);
    (void)xmlTextReaderNodeType(reader);
    (void)xmlTextReaderNodeType(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderIsDefault(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderPrefix(reader);
        if (s)
            xmlFree(s);
    }
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderQuoteChar(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderAttributeCount(reader);
    (void)xmlTextReaderAttributeCount(reader);
    (void)xmlTextReaderAttributeCount(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderPrefix(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderReadState(reader);
    (void)xmlTextReaderReadState(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderLocalName(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasAttributes(reader);
    (void)xmlTextReaderHasAttributes(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderAttributeCount(reader);
    (void)xmlTextReaderAttributeCount(reader);
    (void)xmlTextReaderAttributeCount(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderQuoteChar(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderLocalName(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasAttributes(reader);
    (void)xmlTextReaderHasAttributes(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderReadOuterXml(reader);
        if (s)
            xmlFree(s);
    }
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderNodeType(reader);
    (void)xmlTextReaderNodeType(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderPrefix(reader);
        if (s)
            xmlFree(s);
    }
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderAttributeCount(reader);
    (void)xmlTextReaderAttributeCount(reader);
    (void)xmlTextReaderAttributeCount(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderByteConsumed(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderReadString(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderReadString(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderReadOuterXml(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasAttributes(reader);
    (void)xmlTextReaderHasAttributes(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderDepth(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderPrefix(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderNodeType(reader);
    (void)xmlTextReaderNodeType(reader);
    (void)xmlTextReaderNodeType(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstPrefix(reader);
    (void)xmlTextReaderConstPrefix(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderNamespaceUri(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderNamespaceUri(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderNamespaceUri(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderNamespaceUri(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderNamespaceUri(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderNamespaceUri(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstNamespaceUri(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstString(reader, (const xmlChar*)"fuzzstring");
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderIsEmptyElement(reader);
    (void)xmlTextReaderIsEmptyElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderReadString(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderReadString(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderNext(reader);
    (void)xmlTextReaderNext(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderLocalName(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasAttributes(reader);
    (void)xmlTextReaderHasAttributes(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderNodeType(reader);
    (void)xmlTextReaderNodeType(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderPrefix(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderNormalization(reader);
    (void)xmlTextReaderNormalization(reader);
    (void)xmlTextReaderNormalization(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderPrefix(reader);
        if (s)
            xmlFree(s);
    }
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    (void)xmlTextReaderConstBaseUri(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderReadInnerXml(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderNodeType(reader);
    (void)xmlTextReaderNodeType(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderIsNamespaceDecl(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderPrefix(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderConstLocalName(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderNodeType(reader);
    (void)xmlTextReaderNodeType(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderPrefix(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderConstName(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderLocalName(reader);
        if (s)
            xmlFree(s);
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasAttributes(reader);
    (void)xmlTextReaderHasAttributes(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderMoveToFirstAttribute(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderHasValue(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderMoveToElement(reader);
    (void)xmlTextReaderRead(reader);
    {
        xmlChar *s = xmlTextReaderLookupNamespace(reader, NULL);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderLookupNamespace(reader, NULL);
        if (s)
            xmlFree(s);
    }
    {
        xmlChar *s = xmlTextReaderLookupNamespace(reader, NULL);
        if (s)
            xmlFree(s);
    }
    {
        int attrIndex, n = xmlTextReaderAttributeCount(reader);
        for (attrIndex=0; attrIndex<n; attrIndex++) {
            xmlTextReaderMoveToAttributeNo(reader, attrIndex);
            while (xmlTextReaderReadAttributeValue(reader) == 1);
        }
    }
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderQuoteChar(reader);
    (void)xmlTextReaderRead(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    (void)xmlTextReaderReadAttributeValue(reader);
    (void)xmlTextReaderRead(reader);

    return 0;
}
