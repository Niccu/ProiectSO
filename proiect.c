#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
 
void permisiuni(FILE *file, mode_t mode, char *tipuri_acces)
{
    mode_t permisiuni[] = {S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH};
    fprintf(file, "%s drepturi acces:", tipuri_acces);
    for (int i = 0; i < 3; i++)
    {
        fprintf(file, "%s", (mode & permisiuni[i * 3]) ? "R" : "-");
        fprintf(file, "%s", (mode & permisiuni[i * 3 + 1]) ? "W" : "-");
        fprintf(file, "%s\n", (mode & permisiuni[i * 3 + 2]) ? "X" : "-");
    }
}
 
void citire_director(FILE *fisier_statistici, const char *director, struct dirent *entry)
{
    char path[500];
    sprintf(path, "%s/%s", director, entry->d_name);
    size_t len = strlen(path);
    while (len > 0 && (path[len - 1] == ' ' || path[len - 1] == '\n'))
    {
        path[--len] = '\0';
    }
    struct stat st_file;
    if (stat(path, &st_file) == -1)
    {
        perror("stat error");
        exit(1);
    }
    int uid = (st_file.st_uid);
    fprintf(fisier_statistici, "nume: %s\n", entry->d_name);
    fprintf(fisier_statistici, "id user: %d\n", uid);
 
    char *tipuri_acces[] = {"user", "group", "other"};
    for (int i = 0; i < 3; i++)
    {
        permisiuni(fisier_statistici, st_file.st_mode, tipuri_acces[i]);
    }
    fprintf(fisier_statistici, "\n");
}
 
void fisier_bmp(FILE *fisier_statistici, const char *director, struct dirent *entry)
{
    char path[500] = {};
    sprintf(path, "%s/%s", director, entry->d_name);
    struct stat st_file;
    if (stat(path, &st_file) == -1)
    {
        perror("stat error");
        exit(1);
    }
    if (!S_ISREG(st_file.st_mode))
    {
        perror("nu-i regulat");
        exit(1);
    }
    int uid, links;
    uid = (st_file.st_uid);
    links = (st_file.st_nlink);
 
    int f;
    f = open(path, O_RDONLY);
    if (f == -1)
    {
        perror("eroare deschidere fisier\n");
        exit(1);
    }
    int lungime, inaltime, dimensiune;
    lseek(f, 18, SEEK_SET);
    if (read(f, &inaltime, sizeof(int)) != sizeof(int))
    {
        perror("eroare citire");
        exit(1);
    }
 
    lseek(f, 22, SEEK_SET);
    if (read(f, &lungime, sizeof(int)) != sizeof(int))
    {
        perror("eroare citire");
        exit(1);
    }
 
    lseek(f, 2, SEEK_SET);
    if (read(f, &dimensiune, sizeof(int)) != sizeof(int))
    {
        perror("eroare citire");
        exit(1);
    }
    fprintf(fisier_statistici, "nume fisier: %s\n", entry->d_name);
    fprintf(fisier_statistici, "inaltime: %d\n", inaltime);
    fprintf(fisier_statistici, "lungime: %d\n", lungime);
    fprintf(fisier_statistici, "dimensiune: %d\n", dimensiune);
    fprintf(fisier_statistici, "id utilizator: %d\n", uid);
    fprintf(fisier_statistici, "timpul ultimei modificari: %s\n", ctime(&st_file.st_mtime));
    fprintf(fisier_statistici, "legaturi: %d\n", links);
 
    char *tipuri_acces[] = {"user", "group", "other"};
    for (int i = 0; i < 3; i++)
    {
        permisiuni(fisier_statistici, st_file.st_mode, tipuri_acces[i]);
    }
 
    fprintf(fisier_statistici, "\n");
    close(f);
}
 
void fisier_normal(FILE *fisier_statistici, const char *director, struct dirent *entry)
{
    struct stat st_file;
    char path[500] = {};
    sprintf(path, "%s/%s", director, entry->d_name);
    if (stat(path, &st_file) == -1)
    {
        perror("stat error");
        exit(1);
    }
    if (!S_ISREG(st_file.st_mode))
    {
        perror("nu-i regulat");
        exit(1);
    }
    int uid, links, dimensiune;
    uid = (st_file.st_uid);
    links = (st_file.st_nlink);
    dimensiune = (st_file.st_size);
 
    fprintf(fisier_statistici, "nume fisier: %s\n", entry->d_name);
    fprintf(fisier_statistici, "dimensiune: %d\n", dimensiune);
    fprintf(fisier_statistici, "id utilizator: %d\n", uid);
    fprintf(fisier_statistici, "timpul ultimei modificari: %s\n", ctime(&st_file.st_mtime));
    fprintf(fisier_statistici, "legaturi: %d\n", links);
 
    char *tipuri_acces[] = {"user", "group", "other"};
    for (int i = 0; i < 3; i++)
    {
        permisiuni(fisier_statistici, st_file.st_mode, tipuri_acces[i]);
    }
    fprintf(fisier_statistici, "\n");
}
 
void deschidere_director(const char *director)
{
    DIR *dir;
    dir = opendir(director);
 
    if (dir == NULL)
    {
        perror("eroare deschidere director\n");
        exit(1);
    }
    FILE *fisier_statistici = fopen("statistica.txt", "w");
    if (fisier_statistici == NULL)
    {
        perror("eroare deschidere fisier\n");
        exit(1);
    }
 
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, "..") != 0 && strcmp(entry->d_name, ".") != 0)
        {
            char path[500] = {};
            sprintf(path, "%s/%s", director, entry->d_name);
            size_t len = strlen(path);
            while (len > 0 && (path[len - 1] == ' ' || path[len - 1] == '\n'))
            {
                path[--len] = '\0';
            }
            struct stat st_file;
            if (stat(path, &st_file) == -1)
            {
                perror("stat error\n");
                exit(1);
            }
            if (S_ISDIR(st_file.st_mode))
            {
                citire_director(fisier_statistici, director, entry);
            }
            else if (strstr(entry->d_name, ".bmp") != NULL)
            {
                fisier_bmp(fisier_statistici, director, entry);
            }
            else if (S_ISREG(st_file.st_mode) && !(S_ISLNK(st_file.st_mode)))
            {
                fisier_normal(fisier_statistici, director, entry);
            }
        }
    }
 
    fclose(fisier_statistici);
    if (closedir(dir) == -1)
    {
        perror("eroare inchidere director\n");
        exit(1);
    }
}
 
int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("numar incorect de argumente\n");
        exit(1);
    }
    const char *director = argv[1];
    deschidere_director(director);
    return 0;
}