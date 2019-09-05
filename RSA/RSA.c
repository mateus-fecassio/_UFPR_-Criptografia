#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256


void printBN (char *msg, BIGNUM * a)
{
	// BN_bn2hex(a) for hex string
	// Use BN_bn2dec(a) for decimal string
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}


int main(){

	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *n = BN_new(); 		//contém o produto de dois primos
	BIGNUM *e = BN_new();
	BIGNUM *um = BN_new();
	BIGNUM *phi = BN_new();
	BIGNUM *phi_p = BN_new();
	BIGNUM *phi_q = BN_new();
	BIGNUM *d = BN_new(); 		//guarda a chave privada que será calculada 


	printf("\n\n\n================================\n");
	printf("Task 1: Deriving the Private Key\n");
	printf("================================\n");
	
	//inicializar a, b, n
	//atribui um valor de uma string de número em hexadecimal
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "0D88C3");

	//n = p * q 
	//(e, n) pertencem à chave pública
	BN_mul(n, p, q, ctx);
	printBN("p * q =", n);
	
	//atribui um valor de uma string de número em decimal
	BN_dec2bn (&um, "1");
	//phi = (p-1) * (q-1)
	BN_sub(phi_p, p, um);
	BN_sub(phi_q, q, um);
	BN_mul(phi, phi_p, phi_q, ctx); //phi(n)


	// calcular a chave privada d ===> d * e mod n == 1
	BN_mod_inverse(d, e, phi, ctx);
	printBN("d * e mod n = 1 ===> d =", d);

//----------------------------------------------------------------------

	printf("\n\n\n================================\n");
	printf("Task 2: Encrypting a Message\n");
	printf("================================\n");
	//(e, n) public key

	BIGNUM *msg = BN_new(); 
	BIGNUM *c = BN_new(); 
	//converter de ASCII para hex string
	//converter o hex string para BIGNUM BN hex2bn()


	//mensagem: A top secret!
	BN_hex2bn(&msg, "4120746f702073656372657421");
	printBN("msg [antes da criptografia] = ", msg);

	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&e, "010001");

	//criptografar a mensagem em c ===> c = (m exp e) mod n
	BN_mod_exp(c, msg, e, n, ctx); 
	printBN("c = ", c);

	printf("TESTANDO...\n");
	// c exp d = msg mod n / c exp d mod n = msg
	//	BIGNUM *d = BN_new();
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	BN_mod_exp(msg, c, d, n, ctx); 
	printBN("msg [depois de descriptografado]= ", msg);

//----------------------------------------------------------------------

	printf("\n\n\n================================\n");
	printf("Task 3: Decrypting a Message\n");
	printf("================================\n");


	BIGNUM *C = BN_new();
	BN_hex2bn(&C, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F"); 

	//decrypt the following ciphertext C, and convert it back to a plain ASCII string
	//C exp d = msg exp / c exp d mod n = msg
	BN_mod_exp(msg, C, d, n, ctx);  
	printBN("msg = ", msg);

//----------------------------------------------------------------------

	printf("\n\n\n================================\n");
	printf("Task 4: Signing a Message\n");
	printf("================================\n");
	
	BIGNUM *sig = BN_new();
	
	//mensagem: I owe you $2000.
	printf("mensagem: I owe you $2000.\n");
	BN_hex2bn(&msg, "49206f776520796f752024323030302e");
	BN_mod_exp(sig, msg, d, n, ctx);
	printBN("sig = ", sig);

	//mensagem: I owe you $3000.
	printf("mensagem: I owe you $3000.\n");
	BN_hex2bn(&msg, "49206f776520796f752024333030302e");
	BN_mod_exp(sig, msg, d, n, ctx);
	printBN("sig = ", sig);

//----------------------------------------------------------------------

	printf("\n\n\n================================\n");
	printf("Task 5: Verifying a Signature\n");
	printf("================================\n");
	BIGNUM *S = BN_new();
	BIGNUM *rem = BN_new();
	BIGNUM *Se = BN_new();

	//mensagem: Launch a missile.
	BN_hex2bn(&msg, "4c61756e63682061206d697373696c652e");
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

	BN_exp(Se, S, e, ctx);
	BN_nnmod(rem, msg, n, ctx);

	if (Se == rem)
		printf("Essa assinatura É válida.\n");
	else
		printf("Essa assinatura NÃO É válida\n");


	//pequena alteração na assinatura:
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

	BN_exp(Se, S, e, ctx);
	BN_nnmod(rem, msg, n, ctx);

	printf("após uma pequena alteração na assinatura...\n");
	if (Se == rem)
		printf("Essa assinatura É válida.\n");
	else
		printf("Essa assinatura NÃO É válida\n");

}