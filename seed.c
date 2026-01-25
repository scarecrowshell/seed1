// seed.c -- Seed Core bootstrap: self-integrity + detailed core discovery (no creation)
                                                            // Compile: gcc seed.c -o seed -Wall -O2 -lcrypto

                                                            #define _GNU_SOURCE
                                                            #include <stdio.h>
                                                            #include <stdlib.h>
                                                            #include <string.h>
                                                            #include <dirent.h>
                                                            #include <fcntl.h>
                                                            #include <unistd.h>
                                                            #include <sys/stat.h>
                                                            #include <sys/mman.h>
                                                            #include <time.h>
                                                            #include <elf.h>
                                                            #include <openssl/evp.h>
                                                            #include <errno.h>

                                                            const char *ROOT_REL = "../../"; // path from seed_cores folder up to main/
                                                            const char *DIRS_TO_CHECK[] = { "main_cores", "support_cores", "level_1_cores" };
                                                            const int DIRS_COUNT = sizeof(DIRS_TO_CHECK)/sizeof(DIRS_TO_CHECK[0]);

                                                            static void hexify(const unsigned char *in, size_t inlen, char *out) {
                                                                const char hex[] = "0123456789abcdef";
                                                                for (size_t i = 0; i < inlen; ++i) { out[2*i] = hex[(in[i] >> 4) & 0xF]; out[2*i+1] = hex[in[i] & 0xF]; }
                                                                out[2*inlen] = '\0';
                                                            }

                                                            static int is_elf_file(const char *path) {
                                                                int fd = open(path, O_RDONLY);
                                                                if (fd < 0) return 0;
                                                                unsigned char hdr[4];
                                                                ssize_t r = read(fd, hdr, sizeof(hdr));
                                                                close(fd);
                                                                if (r == 4 && hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F') return 1;
                                                                return 0;
                                                            }

                                                            // Return: 2=functional (exec bit or executable inside dir), 1=present non-exec, 0=missing
                                                            static int check_functional(const char *path) {
                                                                struct stat st;
                                                                if (stat(path, &st) != 0) return 0;

                                                                if (S_ISREG(st.st_mode)) {
                                                                    if (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) return 2;
                                                                    // could accept ELF without exec bit as functional, but keep exec-bit rule
                                                                    return 1;
                                                                } else if (S_ISDIR(st.st_mode)) {
                                                                    DIR *d = opendir(path);
                                                                    if (!d) return 1;
                                                                    struct dirent *e;
                                                                    while ((e = readdir(d)) != NULL) {
                                                                        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
                                                                        char child[4096];
                                                                        if (snprintf(child, sizeof(child), "%s/%s", path, e->d_name) >= (int)sizeof(child)) continue;
                                                                        struct stat cst;
                                                                        if (stat(child, &cst) == 0) {
                                                                            if (S_ISREG(cst.st_mode) && (cst.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) { closedir(d); return 2; }
                                                                        }
                                                                    }
                                                                    closedir(d);
                                                                    return 1;
                                                                } else {
                                                                    return 1;
                                                                }
                                                            }

                                                            static void print_mode_and_exec(struct stat *st) {
                                                                printf("mode=");
                                                                printf( (S_ISDIR(st->st_mode)) ? "d" : "-" );
                                                                printf( (st->st_mode & S_IRUSR) ? "r" : "-" );
                                                                printf( (st->st_mode & S_IWUSR) ? "w" : "-" );
                                                                printf( (st->st_mode & S_IXUSR) ? "x" : "-" );
                                                                printf( (st->st_mode & S_IRGRP) ? "r" : "-" );
                                                                printf( (st->st_mode & S_IWGRP) ? "w" : "-" );
                                                                printf( (st->st_mode & S_IXGRP) ? "x" : "-" );
                                                                printf( (st->st_mode & S_IROTH) ? "r" : "-" );
                                                                printf( (st->st_mode & S_IWOTH) ? "w" : "-" );
                                                                printf( (st->st_mode & S_IXOTH) ? "x" : "-" );
                                                            }

                                                            static void print_timestamp(time_t t) {
                                                                struct tm tm;
                                                                localtime_r(&t, &tm);
                                                                char buf[64];
                                                                strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
                                                                printf("%s", buf);
                                                            }

                                                            static void report_entry_details(const char *rel, const char *abs) {
                                                                struct stat st;
                                                                if (stat(abs, &st) != 0) {
                                                                    printf("    (could not stat: %s)\n", strerror(errno));
                                                                    return;
                                                                }

                                                                if (S_ISREG(st.st_mode)) {
                                                                    printf("    type=file size=%lld ", (long long)st.st_size);
                                                                    print_mode_and_exec(&st);
                                                                    printf(" ");
                                                                    print_timestamp(st.st_mtime);
                                                                    printf(" ");
                                                                    if (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) printf("[executable]");
                                                                    else printf("[non-exec]");
                                                                    if (is_elf_file(abs)) printf(" [ELF]");
                                                                    printf("\n");
                                                                } else if (S_ISDIR(st.st_mode)) {
                                                                    printf("    type=dir ");
                                                                    print_mode_and_exec(&st);
                                                                    printf(" ");
                                                                    print_timestamp(st.st_mtime);
                                                                    // count entries
                                                                    DIR *d = opendir(abs);
                                                                    if (!d) { printf(" [unreadable dir]\n"); return; }
                                                                    int cnt = 0;
                                                                    struct dirent *e;
                                                                    while ((e = readdir(d)) != NULL) {
                                                                        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
                                                                        ++cnt;
                                                                    }
                                                                    closedir(d);
                                                                    printf(" entries=%d\n", cnt);
                                                                } else {
                                                                    printf("    type=other ");
                                                                    print_mode_and_exec(&st);
                                                                    printf(" ");
                                                                    print_timestamp(st.st_mtime);
                                                                    printf("\n");
                                                                }
                                                            }

                                                            int compute_self_hash(char out_hex[65]) {
                                                                const char *self_path = "/proc/self/exe";
                                                                int fd = open(self_path, O_RDONLY);
                                                                if (fd < 0) { perror("open(/proc/self/exe)"); return -1; }

                                                                struct stat st;
                                                                if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return -1; }
                                                                size_t filesize = (size_t)st.st_size;
                                                                if (filesize < sizeof(Elf64_Ehdr)) { fprintf(stderr,"exe too small\n"); close(fd); return -1; }

                                                                void *map = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
                                                                if (map == MAP_FAILED) { perror("mmap"); close(fd); return -1; }

                                                                unsigned char digest[EVP_MAX_MD_SIZE];
                                                                unsigned int digest_len = 0;
                                                                EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
                                                                if (!mdctx) { munmap(map, filesize); close(fd); return -1; }
                                                                if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) { EVP_MD_CTX_free(mdctx); munmap(map, filesize); close(fd); return -1; }

                                                                unsigned char *base = (unsigned char*)map;
                                                                Elf64_Ehdr *eh = (Elf64_Ehdr*)base;

                                                                if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) { fprintf(stderr,"not an ELF\n"); EVP_MD_CTX_free(mdctx); munmap(map, filesize); close(fd); return -1; }
                                                                if (eh->e_ident[EI_CLASS] != ELFCLASS64) { fprintf(stderr,"not ELF64\n"); EVP_MD_CTX_free(mdctx); munmap(map, filesize); close(fd); return -1; }
                                                                if (eh->e_shoff == 0 || eh->e_shnum == 0) { fprintf(stderr,"no sections\n"); EVP_MD_CTX_free(mdctx); munmap(map, filesize); close(fd); return -1; }

                                                                size_t sh_table_end = (size_t)eh->e_shoff + (size_t)eh->e_shnum * (size_t)eh->e_shentsize;
                                                                if (sh_table_end > filesize) { fprintf(stderr,"sh table OOB\n"); EVP_MD_CTX_free(mdctx); munmap(map, filesize); close(fd); return -1; }

                                                                Elf64_Shdr *shdrs = (Elf64_Shdr*)(base + eh->e_shoff);
                                                                if (eh->e_shstrndx == SHN_UNDEF || eh->e_shstrndx >= eh->e_shnum) { fprintf(stderr,"bad shstrndx\n"); EVP_MD_CTX_free(mdctx); munmap(map, filesize); close(fd); return -1; }
                                                                Elf64_Shdr *sh_strtab = &shdrs[eh->e_shstrndx];
                                                                if ((size_t)sh_strtab->sh_offset + (size_t)sh_strtab->sh_size > filesize) { fprintf(stderr,"shstrtab OOB\n"); EVP_MD_CTX_free(mdctx); munmap(map, filesize); close(fd); return -1; }
                                                                const char *shstr = (const char*)(base + sh_strtab->sh_offset);

                                                                int found_any = 0;
                                                                for (int i = 0; i < eh->e_shnum; ++i) {
                                                                    const char *name = shstr + shdrs[i].sh_name;
                                                                    size_t sh_off = (size_t)shdrs[i].sh_offset;
                                                                    size_t sh_sz  = (size_t)shdrs[i].sh_size;
                                                                    if (sh_sz == 0) continue;
                                                                    if (sh_off + sh_sz > filesize) continue;
                                                                    if (strcmp(name, ".text") == 0 || strcmp(name, ".rodata") == 0) {
                                                                        if (EVP_DigestUpdate(mdctx, base + sh_off, sh_sz) != 1) { EVP_MD_CTX_free(mdctx); munmap(map, filesize); close(fd); return -1; }
                                                                        found_any = 1;
                                                                    }
                                                                }
                                                                if (!found_any) { fprintf(stderr,"no .text/.rodata\n"); EVP_MD_CTX_free(mdctx); munmap(map, filesize); close(fd); return -1; }

                                                                if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) { EVP_MD_CTX_free(mdctx); munmap(map, filesize); close(fd); return -1; }
                                                                EVP_MD_CTX_free(mdctx);

                                                                hexify(digest, digest_len, out_hex);
                                                                munmap(map, filesize);
                                                                close(fd);
                                                                return 0;
                                                            }

                                                            int scan_and_report_dir(const char *root_rel, const char *dir_name, int *out_total, int *out_functional, int *out_present_nonexec, int *out_missing) {
                                                                char path[4096];
                                                                if (snprintf(path, sizeof(path), "%s%s", root_rel, dir_name) >= (int)sizeof(path)) { fprintf(stderr,"path too long\n"); return -1; }

                                                                struct stat st;
                                                                if (stat(path, &st) != 0) {
                                                                    printf("DIR[%s]: MISSING (%s)\n", dir_name, path);
                                                                    *out_missing += 1;
                                                                    return 0;
                                                                }
                                                                if (!S_ISDIR(st.st_mode)) {
                                                                    printf("DIR[%s]: NOT A DIRECTORY (%s)\n", dir_name, path);
                                                                    *out_missing += 1;
                                                                    return 0;
                                                                }

                                                                DIR *d = opendir(path);
                                                                if (!d) {
                                                                    printf("DIR[%s]: UNREADABLE (%s)\n", dir_name, path);
                                                                    *out_missing += 1;
                                                                    return 0;
                                                                }

                                                                struct dirent *e;
                                                                int found_any = 0;
                                                                while ((e = readdir(d)) != NULL) {
                                                                    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
                                                                    found_any = 1;
                                                                    char entry_rel[4096];
                                                                    if (snprintf(entry_rel, sizeof(entry_rel), "%s/%s", dir_name, e->d_name) >= (int)sizeof(entry_rel)) continue;
                                                                    char entry_abs[4096];
                                                                    if (snprintf(entry_abs, sizeof(entry_abs), "%s%s/%s", root_rel, dir_name, e->d_name) >= (int)sizeof(entry_abs)) continue;

                                                                    int status = check_functional(entry_abs);
                                                                    (*out_total)++;
                                                                    if (status == 2) { printf("CORE[%s]: FUNCTIONAL (%s)\n", entry_rel, entry_abs); (*out_functional)++; report_entry_details(entry_rel, entry_abs); }
                                                                    else if (status == 1) { printf("CORE[%s]: PRESENT_NONEXEC (%s)\n", entry_rel, entry_abs); (*out_present_nonexec)++; report_entry_details(entry_rel, entry_abs); }
                                                                    else { printf("CORE[%s]: MISSING (%s)\n", entry_rel, entry_abs); (*out_missing)++; }
                                                                }
                                                                closedir(d);

                                                                if (!found_any) {
                                                                    printf("DIR[%s]: EMPTY (%s) -- no cores present\n", dir_name, path);
                                                                }
                                                                return 0;
                                                            }

                                                            int main(int argc, char **argv) {
                                                                printf("SEED: process started (pid=%d)\n", (int)getpid());

                                                                char got_hex[65] = {0};
                                                                if (compute_self_hash(got_hex) != 0) {
                                                                    printf("SELF_CHECK: FAIL (could not compute self hash)\nSEED_STATE: HALT\n");
                                                                    return 3;
                                                                }
                                                                printf("SELF_HASH: %s\n", got_hex);

                                                                // Auto-save & verify against itself
                                                                FILE *hf = fopen("self_hash.txt", "w");
                                                                if (hf) { fprintf(hf, "%s\n", got_hex); fclose(hf); printf("SELF_HASH saved to self_hash.txt\n"); }
                                                                else perror("failed to write self_hash.txt");

                                                                printf("SELF_CHECK: PASS\n");

                                                                int total = 0, functional = 0, present_nonexec = 0, missing = 0;

                                                                for (int i = 0; i < DIRS_COUNT; ++i) {
                                                                    scan_and_report_dir(ROOT_REL, DIRS_TO_CHECK[i], &total, &functional, &present_nonexec, &missing);
                                                                }

                                                                printf("MANIFEST_SUMMARY: total=%d functional=%d present_nonexec=%d missing=%d\n", total, functional, present_nonexec, missing);

                                                                if (total == 0) {
                                                                    printf("SEED_STATE: PARTIAL (no cores found)\n");
                                                                    return 2;
                                                                } else if (functional == total) {
                                                                    printf("SEED_STATE: READY\n");
                                                                    return 0;
                                                                } else if (functional > 0) {
                                                                    printf("SEED_STATE: DEGRADED (some cores present but not all functional)\n");
                                                                    return 2;
                                                                } else {
                                                                    printf("SEED_STATE: PARTIAL (no functional cores)\n");
                                                                    return 2;
                                                                }
                                                            }
