/*This is a program to illustrate
 *the shared memory control, shmctl(),
 *system call capabilities.
 */

/*Include necessary header files.*/
#include    <stdio.h>
#include    <sys/types.h>
#include    <sys/ipc.h>
#include    <sys/shm.h>
#include    <unistd.h>
#include    <string.h>
#include    <stdlib.h>

/*Start of main C language program*/
int main(int argc, char *argv[])
{
	int uid, gid, mode;
	int rtrn, shmid, command, choice;
	struct shmid_ds shmid_ds, *buf;
	buf = & shmid_ds;


	shmid = atoi(argv[1]);
#if 0
	/*Get the shmid, and command.*/
	printf("Enter the shmid = ");
	scanf("%d", &shmid);
	printf("\nEnter the number for\n");
	printf("the desired command:\n");


	printf("IPC_STAT    =  1\n");
	printf("IPC_SET     =  2\n");
	printf("IPC_RMID    =  3\n");
	printf("SHM_LOCK    =  4\n");
	printf("SHM_UNLOCK  =  5\n");
	printf("Entry       =  ");
	scanf("%d", &command);
#endif
	command = 1;


	/*Check the values.*/
	printf ("\nshmid =%d, command = %d\n",
			shmid, command);


	switch (command)
	{
		case 1:    /*Use shmctl() to get
			     the data structure for
			     shmid in the shmid_ds area pointed
			     to by buf and then print it out.*/
			rtrn = shmctl(shmid, IPC_STAT, buf);
			printf ("\nThe USER ID = %d\n", buf->shm_perm.uid);
			printf ("The GROUP ID = %d\n", buf->shm_perm.gid);
			printf ("The creator's ID = %d\n", buf->shm_perm.cuid);
			printf ("The creator's group ID = %d\n", buf->shm_perm.cgid);
			printf ("The operation permissions = 0%o\n", buf->shm_perm.mode);
			printf ("The slot usage sequence\n");
			printf ("number = 0%x\n", buf->shm_perm.__seq);
			printf ("The key= 0%x\n", buf->shm_perm.__key);
			printf ("The segment size = %d\n", buf->shm_segsz);
			printf ("The pid of last shmop = %d\n", buf->shm_lpid);
			printf ("The pid of creator = %d\n", buf->shm_cpid);
			printf ("The current # attached = %d\n", buf->shm_nattch);
			printf("The last shmat time = %ld\n", buf->shm_atime);
			printf("The last shmdt time = %ld\n", buf->shm_dtime);
			printf("The last change time = %ld\n", buf->shm_ctime);
			break;


			/* Lines 71 - 85 deleted */


		case 2:    /*Select and change the desired
			     member(s) of the data structure.*/


			/*Get the original data for this shmid
			  data structure first.*/
			rtrn = shmctl(shmid, IPC_STAT, buf);


			printf("\nEnter the number for the\n");
			printf("member to be changed:\n");
			printf("shm_perm.uid   = 1\n");
			printf("shm_perm.gid   = 2\n");
			printf("shm_perm.mode  = 3\n");
			printf("Entry          = ");
			scanf("%d", &choice);


			switch(choice){
				case 1:
					printf("\nEnter USER ID = ");
					scanf ("%d", &uid);
					buf->shm_perm.uid = uid;
					printf("\nUSER ID = %d\n",
							buf->shm_perm.uid);
					break;


				case 2:
					printf("\nEnter GROUP ID = ");
					scanf("%d", &gid);
					buf->shm_perm.gid = gid;
					printf("\nGROUP ID = %d\n",
							buf->shm_perm.gid);
					break;


				case 3:
					printf("\nEnter MODE in octal = ");
					scanf("%o", &mode);
					buf->shm_perm.mode = mode;
					printf("\nMODE = 0%o\n",
							buf->shm_perm.mode);
					break;
			}
			/*Do the change.*/
			rtrn = shmctl(shmid, IPC_SET,
					buf);
			break;


		case 3:    /*Remove the shmid along with its
			     associated
			     data structure.*/
			rtrn = shmctl(shmid, IPC_RMID, (struct shmid_ds *) NULL);
			break;


		case 4: /*Lock the shared memory segment*/
			rtrn = shmctl(shmid, SHM_LOCK, (struct shmid_ds *) NULL);
			break;
		case 5: /*Unlock the shared memory
			  segment.*/
			rtrn = shmctl(shmid, SHM_UNLOCK, (struct shmid_ds *) NULL);
			break;
	}
	/*Perform the following if the call is unsuccessful.*/
	if(rtrn == -1)
	{
		perror("\nThe shmctl call failed, error number\n");
	}
	/*Return the shmid upon successful completion.*/
	else
		printf ("\nShmctl was successful for shmid = %d\n",
				shmid);
	return 0;
}
