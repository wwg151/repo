// From repository root: filter a dpkg-scanpackages index on stdin to stdout.
#define _GNU_SOURCE
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
    int add=ids==1 && (!links || (links==1 && empty<n)) && managed(q,id);
    for(size_t i=0;i<n;i++) {
        // Insert before the first field, not after a possibly unterminated last line.
        if(add && ((!links && i==0) || (links && i==empty))) {
            const char *eol=strstr(lines[i],"\r\n")?"\r\n":(links && !strchr(lines[i],'\n')?"":"\n");
            printf("SileoDepiction: https://wwg151.github.io/depictions/%s/depiction.json%s",id,eol);
            if(links) continue;
        }
        fputs(lines[i],stdout);
    }
    free(id);
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
