#include <stdio.h>
#include <string.h>
#include <crypt.h>
#include <stdlib.h>
#include <omp.h>
 
void chop(char *word){
  int lenword=strlen(word);
  if(word[lenword-1] == '\n')   word[lenword-1] = '\0';
}
 
int numlines(FILE *file){
        if(file==NULL)  return -1;
        char ch;
        int lines = 0;
        while (ch != EOF){
                ch = fgetc(file);
                if(ch == '\n')  lines++;       
        }
        return lines;
}
 
void main(int argc, char *argv[]){
  //Parameters error handling
  if(argc!=4){
        printf("Parallel SHA-512 Password Cracker\nUSAGE: ./parshacrk <PATH TO DICTIONARY> '$6$<SALT>$' '$6$<SALT>$<SHA-512 HASH>'\n");
        exit(-1);
  }
  int found=0;  //0 = password not found ; 1 = password found
  char word[BUFSIZ],salt[BUFSIZ], pwhash[BUFSIZ];
  FILE *words = fopen(argv[1],"r");     //Open dictionary file
  //File error handling
  if(words==NULL){
        printf("Cannot open dictionary file.\n");      
        exit(-1);      
  }
  strcpy(salt,argv[2]);
  strcpy(pwhash,argv[3]);
  int size = numlines(words); // Number of words in dictionary
  if(fseek(words,0,SEEK_SET)==-1)       exit(-1);       //seek error handling
  //Parallel Region
  #pragma omp parallel for private(word) shared(found) schedule(dynamic)
  for(int i=0;i<size;i++){
        if(fgets(word,BUFSIZ,words) != NULL){
                chop(word);
                if(found==1)    exit(1);
                printf("[*] THREAD %i TRYING: %s\n",omp_get_thread_num(),word);
                char *hash = (char*)crypt(word,salt);
                if(strcmp(hash,pwhash) == 0){
                        printf("[+] PASSWORD FOUND: %s\n",word);
                        found=1;
                }
        }
  }
  fclose(words);
  if(found==0)  printf("[-] PASSWORD NOT FOUND, EXITING...\n");
  exit(0);
}
