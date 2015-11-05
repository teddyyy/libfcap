#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int opt, channel = 0;

	if (argc <= 1) {
		printf("Too few options\n");
		return -1;
	}

	while ((opt = getopt(argc, argv, "c:")) > 0) {
		switch(opt) {
			case 'c':
				channel = atoi(optarg);
				break;
			default:
				printf("Unknown option %c\n", opt);
				break;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc > 0) {
		printf("Too many options\n");
		return -1;
	}	

	init_fcap(argc, argv, channel);

	return 0;
}
