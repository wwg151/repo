// From repository root: filter a dpkg-scanpackages index on stdin to stdout.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sqlite3.h>

static void die(const char *why) { fprintf(stderr,"link-depictions: %s\n",why); exit(1); }
static int regular(const char *path, int dir) {
    struct stat st;
    if (lstat(path,&st)) {
        if (errno==ENOENT || errno==ENOTDIR) return 0;
        die(path);
    }
    return dir ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode);
}
static int managed(sqlite3_stmt *q,const char *id) {
    if (!*id || !isalnum((unsigned char)*id) || strspn(id,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.+-")!=strlen(id)) return 0;
    char *dir=NULL,*file=NULL;
    if (asprintf(&dir,"depictions/%s",id)<0 || asprintf(&file,"%s/depiction.json",dir)<0) die("allocation");
    int ok=regular("depictions",1) && regular(dir,1) && regular(file,0);
    if (ok) {
        FILE *f=fopen(file,"rb"); if (!f) die(file);
        char *doc=NULL; size_t cap=0; ssize_t n=getdelim(&doc,&cap,0,f);
        if (ferror(f)) die(file);
        fclose(f); ok=0;
        if (n>0 && !memchr(doc,0,n)) {
            if (sqlite3_bind_text(q,1,doc,(int)n,SQLITE_TRANSIENT)!=SQLITE_OK || sqlite3_step(q)!=SQLITE_ROW) die("JSON query failed");
            ok=sqlite3_column_int(q,0); sqlite3_reset(q);
        }
        free(doc);
    }
    free(dir); free(file); return ok;
}
// Only an explicit source.json can replace existing addresses.
typedef struct { char *mode, *web, *native; } Policy;
static int https_url(const char *s) {
    if (strncasecmp(s,"https://",8) || !s[8]) return 0;
    const char *host=s+8, *end=host+strcspn(host,"/?#"), *p=host;
    if (*p=='[') {
        const char *br=memchr(p,']',end-p); struct in6_addr addr;
        if (!br || br-p>=INET6_ADDRSTRLEN) return 0;
        char ip[INET6_ADDRSTRLEN]; memcpy(ip,p+1,br-p-1); ip[br-p-1]=0;
        if (inet_pton(AF_INET6,ip,&addr)!=1) return 0;
        p=br+1;
    } else {
        while (p<end && (isalnum((unsigned char)*p) || *p=='.' || *p=='-')) p++;
        if (p==host) return 0;
    }
    if (p<end) {
        if (*p++!=':' || p==end) return 0;
        unsigned port=0; while (p<end) { if (!isdigit((unsigned char)*p)) return 0; port=port*10+(*p++-'0'); if(port>65535) return 0; }
        if (!port) return 0;
    }
    for (p=end; *p; p++) if ((unsigned char)*p<=32 || (unsigned char)*p>=127 || strchr("\\<>\"",*p)) return 0;
    return 1;
}
static Policy policy(sqlite3_stmt *marker,const char *id) {
    Policy result={0};
    if (!*id || !isalnum((unsigned char)*id) || strspn(id,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.+-")!=strlen(id)) return result;
    char *dir,*path;
    if (asprintf(&dir,"depictions/%s",id)<0 || asprintf(&path,"%s/source.json",dir)<0) die("allocation");
    struct stat st;
    if (!regular("depictions",1) || !regular(dir,1)) goto done;
    if (lstat(path,&st)<0) { if(errno!=ENOENT) die(path); goto done; }
    if (!S_ISREG(st.st_mode) || st.st_size>65536) die(path);
    FILE *f=fopen(path,"rb"); if (!f) die(path);
    char *doc=NULL; size_t cap=0; ssize_t len=getdelim(&doc,&cap,0,f);
    if (ferror(f) || len<=0 || memchr(doc,0,len) || strstr(doc,"\\u0000")) die(path);
    fclose(f);
    sqlite3_stmt *q; sqlite3 *db=sqlite3_db_handle(marker);
    if(sqlite3_prepare_v2(db,"SELECT key,type,value FROM json_each(CASE WHEN json_valid(?1) AND json_type(CASE WHEN json_valid(?1) THEN ?1 END)='object' THEN ?1 ELSE '{}' END)",-1,&q,NULL)!=SQLITE_OK || sqlite3_bind_text(q,1,doc,(int)len,SQLITE_STATIC)!=SQLITE_OK) die(path);
    int rc;
    while ((rc=sqlite3_step(q))==SQLITE_ROW) {
        const char *key=(const char *)sqlite3_column_text(q,0);
        char **slot=!strcmp(key,"mode")?&result.mode:!strcmp(key,"depiction")?&result.web:!strcmp(key,"sileoDepiction")?&result.native:NULL;
        if (!slot || *slot || strcmp((const char *)sqlite3_column_text(q,1),"text")) die(path);
        const char *v=(const char *)sqlite3_column_text(q,2);
        if (!v || strlen(v)!=(size_t)sqlite3_column_bytes(q,2) || !(*slot=strdup(v))) die(path);
    }
    sqlite3_finalize(q); free(doc);
    if (rc!=SQLITE_DONE || !result.mode) die(path);
    if (!strcmp(result.mode,"custom")) {
        if ((!result.web && !result.native) || (result.web && !https_url(result.web)) || (result.native && !https_url(result.native))) die(path);
    } else if (!strcmp(result.mode,"repodock")) {
        char *html; if(asprintf(&html,"%s/index.html",dir)<0) die("allocation");
        if (!regular(html,0) || !managed(marker,id)) die(path);
        free(html); free(result.web); free(result.native);
        if (asprintf(&result.web,"https://wwg151.github.io/%s/",dir)<0 || asprintf(&result.native,"%sdepiction.json",result.web)<0) die("allocation");
    } else if (strcmp(result.mode,"original")) die(path);
done:
    free(dir); free(path); return result;
}
static void emit(sqlite3_stmt *q,char **lines,size_t n) {
    char *id=NULL; size_t ids=0, links=0,empty=n;
    for (size_t i=0;i<n;i++) {
        char *s=lines[i];
        if (!strncasecmp(s,"Package:",8)) {
            ids++; s+=8; s+=strspn(s," \t"); free(id); id=strdup(s); if (!id) die("allocation");
            id[strcspn(id,"\r\n")]=0; size_t len=strlen(id); while(len && strchr(" \t",id[len-1])) id[--len]=0;
        } else if (!strncasecmp(s,"SileoDepiction:",sizeof("SileoDepiction:")-1)) {
            links++; const char *v=s+sizeof("SileoDepiction:")-1; if (!v[strspn(v," \t\r\n")] && (i+1==n || !strchr(" \t",lines[i+1][0]))) empty=i;
        }
    }
    Policy source={0};
    if (ids==1) source=policy(q,id);
    int replace=source.mode && strcmp(source.mode,"original");
    int add=!source.mode && ids==1 && (!links || (links==1 && empty<n)) && managed(q,id);
    int skip=0;
    if (replace) {
        const char *nl=strstr(lines[0],"\r\n")?"\r\n":"\n";
        if(source.web) printf("Depiction: %s%s",source.web,nl);
        if(source.native) printf("SileoDepiction: %s%s",source.native,nl);
    }
    for(size_t i=0;i<n;i++) {
        if (replace) {
            if (*lines[i]!=' ' && *lines[i]!='\t')
                skip=!strncasecmp(lines[i],"Depiction:",9) || !strncasecmp(lines[i],"SileoDepiction:",15);
            if(skip) continue;
        }
        // Insert before the first field, not after a possibly unterminated last line.
        if(add && ((!links && i==0) || (links && i==empty))) {
            const char *eol=strstr(lines[i],"\r\n")?"\r\n":(links && !strchr(lines[i],'\n')?"":"\n");
            printf("SileoDepiction: https://wwg151.github.io/depictions/%s/depiction.json%s",id,eol);
            if(links) continue;
        }
        fputs(lines[i],stdout);
    }
    free(source.mode); free(source.web); free(source.native); free(id);
}
int main(void) {
    sqlite3 *db; sqlite3_stmt *q;
    // Count the root key as well as matching its type: duplicate markers are ambiguous.
    const char *sql="SELECT CASE WHEN json_valid(?1) AND json_type(CASE WHEN json_valid(?1) THEN ?1 END)='object' THEN (SELECT count(*)=1 AND max(type='integer' AND value=1) FROM json_each(?1) WHERE key='repoDockChangelog') ELSE 0 END";
    if(sqlite3_open(":memory:",&db)!=SQLITE_OK || sqlite3_prepare_v2(db,sql,-1,&q,NULL)!=SQLITE_OK) die("SQLite JSON1 required");
    char **lines=NULL,*s=NULL; size_t n=0,cap=0,max=0; ssize_t len;
    while ((len=getline(&s,&cap,stdin))>=0) {
        if(memchr(s,0,len)) die("NUL in Packages");
        if(!strcmp(s,"\n") || !strcmp(s,"\r\n")) {
            emit(q,lines,n); while(n) free(lines[--n]); fputs(s,stdout);
        } else {
            if(n==max) { max=max?2*max:16; lines=realloc(lines,max*sizeof(*lines)); if(!lines) die("allocation"); }
            lines[n++]=s; s=NULL;cap=0;
        }
    }
    if(ferror(stdin)) die("Packages read failed");
    emit(q,lines,n); while(n) free(lines[--n]); free(lines); free(s);
    sqlite3_finalize(q); sqlite3_close(db); return fflush(stdout) || ferror(stdout);
}
