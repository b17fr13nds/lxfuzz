inline void error(const char *str) {
  perror(str);
  exit(-1);
}
