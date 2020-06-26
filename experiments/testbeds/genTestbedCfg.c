#include <stdio.h>
#include <stdlib.h>

//#define nEncs 64
//#define nApps 4
//#define nLems 2

int
main(int argc, char **argv)
{
  int nEncs = 0;
  int nApps = 0;
  int nLems = 0;
  
  if (argc < 4)
  {
    printf("usage: genTestbedCfg nEnclaves nAppNodesPerEnclave nLinkEmsPerEnclave\n");
    exit(0);
  }

  nEncs = atoi(argv[1]);
  nApps = atoi(argv[2]);
  nLems = atoi(argv[3]);

  if ((nEncs < 2) || (nApps < 1) || (nLems < 1))
  {
    printf("nEnclaves must be at least 2\n");
    printf("nAppNodesPerEnclave must be at least 1\n");
    printf("nLinkEmsPerEnclave must be at least 1\n");
    exit(0);
  }
  
  int links_per_enclave = nApps + nLems + nLems; // two links per link emulator
  int nodes_per_enclave = nApps + 1 + nLems;     // routers aren't counted

  printf("suffix bbn.com\n");
  printf("\n");
  printf("exp_base_dir /home/${USER_NAME}\n");
  printf("results_location ${HOME}/iron_results\n");
  printf("\n");
  printf("num_enclaves %d\n",nEncs);
  printf("app_nodes_per_enclave %d\n",nApps);
  printf("le_nodes_per_enclave %d\n",nLems);
  printf("\n");

  int node_offset = 1;
  int link_offset = 1;
  
  for (int enc=0; enc<nEncs; enc++)
  {
    int node      = node_offset + enc * nodes_per_enclave;
    int link      = link_offset + enc * links_per_enclave;
    int gnat_node = node + nApps;
    
    // First the app nodes connected to the GNAT node
    for (int i=0; i<nApps; i++)
    {
      printf("link%d node%d node%d\n",link,node,gnat_node);
      link++;
      node++;
    }
    
    // Next the GNAT node to the link emulators and router node
    // Advance past the GNAT node
    node++;
    
    for (int i=0; i<nLems; i++)
    {
      printf("link%d node%d node%d\n",link,gnat_node,node);
      link++;
      printf("link%d node%d rtr%d\n",link,node,enc+1);
      link++;
      node++;
    }
  }

  for (int enc=0; enc<nEncs; enc++)
  {
    int node      = node_offset + enc * nodes_per_enclave;
    int link      = link_offset + enc * links_per_enclave;
    int gnat_node = node + nApps;

    printf("\n# Enclave %d\n",enc+1);

    // First the app nodes connected to the GNAT node
    for (int i=0; i<nApps; i++)
    {
      printf("node%d gnat-app%d-%d link%d=10.%d.3.%d\n",node,enc+1,i+1,
	     link,enc+1,i+2);
      node++;
      link++;
    }

    // Reset link for the next section
    link = link_offset + enc * links_per_enclave;
    
    // Next the GNAT node
    printf("node%d gnat%d link%d=10.%d.3.1",node,enc+1,link,enc+1);
    link++;
    for (int i=0; i<nLems; i++)
    {
      printf(",link%d=10.%d.%d.2",link,enc+1,i+1);
      link+=2;
    }
    printf("\n");
    node++;
    
    // Reset link for the next section
    link = link_offset + enc * links_per_enclave + nApps;

    // Next the GNAT node to the link emulators and router node
    // Advance past the GNAT node

    for (int i=0; i<nLems; i++)
    {
      printf("node%d gnat-le%d link%d=10.%d.%d.102,link%d=10.%d.%d.101\n",
	     node,enc+1,link,enc+1,i+1,link+1,enc+1,i+1);
      link+=2;
      node++;
    }
  }
}
    
