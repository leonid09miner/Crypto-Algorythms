#include <gmpxx.h>
#include <cmath>
#include <ctime>
#include <sys/random.h>
#include <string>
#include "rsa2048.hpp"

// large modulo multiplication
mpz_class mulsl(mpz_class a, mpz_class b, mpz_class m)
{
	if (b == 1)
		return a;

	std::string mul = b.get_str(2);
	mpz_class res = 0;
	mpz_class tmp;

	for (int i = 0; i < mul.length(); i++)
	{
		tmp = res * 2 % m;

		if (mul[i] == '1')
			tmp = (tmp + a) % m;

		res = tmp;
	}
	return res;
}

// large modulo degree
mpz_class powsl(mpz_class a, mpz_class b, mpz_class m)
{
	if (b == 0)
		return 1;

	std::string pow = b.get_str(2);
	mpz_class res = 1;
	mpz_class tmp;

	for (int i = 0; i < pow.length(); i++)
	{
		tmp = res * res % m;

		if (pow[i] == '1')
			tmp = tmp * a % m;
		
		res = tmp;
	}
	return res;
}

// find large greatest common divisor via extended euclid algorithm
mpz_class euclGCDl(mpz_class a, mpz_class b)
{
	mpz_class r0;
	mpz_class r1;
	if (a > b)
	{
		r0 = a;
		r1 = b;
	}
	else 
	{
		r0 = b;
		r1 = a;
	}
	mpz_class q;
	mpz_class tmp;

	while(r1 != 0)
	{
		q = r0 / r1;

		tmp = r1;
		r1 = r0 - r1 * q;
		r0 = tmp;
	}

	return r0;
}

// find large inverse number via extended euclid algorithm
mpz_class findInvl(mpz_class a, mpz_class m)
{
	mpz_class t0 = 0;
	mpz_class t1 = 1;

	mpz_class r0 = m;
	mpz_class r1 = a;
	
	mpz_class q;
	mpz_class tmp;

	while(r1 != 0)
	{
		q = r0 / r1;

		tmp = r1;
		r1 = r0 - r1 * q;
		r0 = tmp;

		tmp = t1;
		// t1 = t0 - t1 * q;
		t1 = (t0 - mulsl(t1, q, m) + m) % m;
		t0 = tmp;
	}

	return t0;
}

// large Miller-Rabin check
bool millerRabinl(mpz_class n)
{
	if (n == 2)
		return 1;

	mpz_class d = n - 1;
	mpz_class s = 0;
	while (d % 2 == 0)
	{
		d /= 2;
		s += 1;
	}

	gmp_randclass rng(gmp_randinit_mt);
	rng.seed(time(nullptr));

	for (int i = 0; i < 50; i++)
	{
		mpz_class a = rng.get_z_bits(1024) % (n - 2) + 2;

		if (euclGCDl(a, n) != 1)
			return 0;

		mpz_class x = powsl(a, d, n);
		if (x == 1 || x == n - 1)
			continue;
		
		bool pr = 0;
		for (int j = 0; j < s - 1 && !pr; j++)
		{
			x = powsl(x, 2, n);
			if (x == n - 1)
				pr = 1;
		}
		
		if (!pr)
			return 0;
	}
	return 1;
}

// generate large prime number
mpz_class generatePrime()
{
	unsigned char buf[128];
	size_t buflen = 128;
	ssize_t len = 0;
	mpz_class res = 0;

	mpz_class mask = 0x1;
	mask = mask << 1023 | 0x1;

	len = getrandom(buf, buflen, 0);
	for (int i = 0; i < 128; i++)
	{
		mpz_class tmp = buf[i];
		res |= tmp << ((127 - i) * 8);
	}
	res |= mask;

	bool pr = false;
	while(!pr)
	{
		if (millerRabinl(res))
			pr = true;
		else 
			res += 2; // res = 0;
	}
	return res;
}

// generate large RSA keys
mpz_class* generateLargeKeys()
{
	bool pr = false;

	mpz_class p;
	mpz_class q;
	p = generatePrime();
	while (!pr)
	{
		q = generatePrime();
		mpz_class dif = 0x01_mpz << 1000;
		if (abs(p - q) >= dif)
			pr = true;
	}

	mpz_class phi = (p - 1) * (q - 1);

	mpz_class publicKey;
	pr = false;

	unsigned char buf[128];
	size_t buflen = 128;
	ssize_t len = 0;	

	while (!pr)
	{
		len = getrandom(buf, buflen, 0);
		for (int i = 0; i < 128; i++)
		{
			mpz_class tmp = buf[i];
			publicKey |= tmp << ((127 - i) * 8);
		}
		publicKey %= phi;

		if (euclGCDl(publicKey, phi) == 1)
			pr = true;
		else 
			publicKey = 0_mpz;
	}

	mpz_class privateKey = findInvl(publicKey, phi);

	mpz_class* keys = new mpz_class[3];
	keys[0] = p * q;
	keys[1] = publicKey;
	keys[2] = privateKey;

	return keys;
}

// generate large prime number
mpz_class generate256Prime()
{
	unsigned char buf[1920];
	size_t buflen = 1920;
	ssize_t len = 0;
	mpz_class res = 0;

	mpz_class mask = 0x1;
	mask = mask << 15359 | 0x1;

	len = getrandom(buf, buflen, 0);
	for (int i = 0; i < 1920; i++)
	{
		mpz_class tmp = buf[i];
		res |= tmp << ((1919 - i) * 8);
	}
	res |= mask;

	bool pr = false;
	while(!pr)
	{
		if (millerRabinl(res))
			pr = true;
		else 
			res += 2; // res = 0;
	}
	return res;
}

mpz_class* generate256Keys()
{
	mpz_class p = 0xca3532dac6d70967050be1e3e9680e0af391dd296b9737596e0f136fb6ca09fe279c919346edbe6b6231218b835b4cbf57a7eb655d17e31a1c50df77c54a8d8de5549fa9f86d94842beb95a3f68806069ea1bfee14090455caf8316e472d1e851d160099dd6ca18690a36b0552822b5a44397bbc09afb52405f4f631746ada28ad274d7d8276407870674428ff77a1dadc0c988871577aa46dfc5e6d36b725e07c0b7cf430cfac65a1c81463ba5eed59e038cdf4f223cc1046a6d39b511120e56e3f47bfe671d03396633d3d9f98cc6ac4b0052b656af9582d043da2e76c7d336fb0e6b01f5f161c8df3ce920c6fd05de36088dd8936cabcac9334f6e664a0b1d21d658177e0f97ef4cc887b527acead9987581b8fb4d9d9e333e75cbe7eacb33f25a3bca0f2e330b77cccb8cfab833a0819bc5eebf212ede0a54873c079c4227a5f165218d57907dc26c38c3789b695dfd472cc608fb58495db399a2a8e6dc19ff239617c48488fd584027ff96252d5340daf810b30f91269ce13117d629f66ad39853185644c512f34ef773b8f889513b18bb5283013fb02f1f58d4d62492fe80d672eb35833d53880f14e8d9788c7375acf0bf5a3772b44c7d18f31a7ff2ff852f277d3b28fd15adf7791fbb3622ab6d91820fc8f6facaa395af6c652098b108990b11c17b291b317c12e8a6762f388a807fd4ddc7651316b8f31e04fbf06d71e7fce71454fd6d8f3a05e2d2fa99a565d8b9dc893107761b9bdb4796fa9072e82369bc81593eb92ae73a48f782eba75bcb1c3d90db83e5016035b37fd538aaa2ab814c2c71bb7d01eeeb14e0908b19e11a0674abab27d55aa2e94c936771e1ad5a421876f075afb1148e4f6de62f8b62eaa257f115c1c0bc2d0b8df2928a75f23fba595aa8346fc8c944b55838a9ce39770c5fd34f46649a4d5492f700db57fdb6653982f80203b5c6e6dab0e4e23a4269ee80b37bb23703a1adc8de5fcc8241bc80f197d5c368379c6fec9482bce212678ea529a0b2ebe74b6f92a52f0054d0c86ed7c9b5d7d89e101ae4eac54555d50e994faa3e4829ea4db683f6d81373cb649bbca813da432c2b2b5422849693ff031199bddb75f91e288386d211fce05d823b871d23498b1142092c3adf135c3dc95e4eb626a0f3d7626d5e7965a5b3b787070b7bb164f50f8cfaad89a76d66863c2c9b2cbedda983a3e973b0788fa9d16eda6e44aeaeca12d170878167b0fab1f73d8123f3df091561f7f3f7bb498f69aa81f46b1e9e90571d0900ed9170262cad3063e6cffdef68c3322ae3e8eb56779db056f8e803fb45ebd2ba7b5dcd7efd47efcc8581738870526cfbed370e5_mpz;
	mpz_class q = 0xe96caec157ba4600117e2a1f521086eede07231082b3f3c60b198225783c7b1c8624ab32754669774bb2f4e14fa394f7ea495dcfa66f349fb709dc981fb7e8947745cac8c801317d61072e7d723c76bcc2f98fc08f32212a37c0434af7604b00b825d1fa8d40ae97b445c706bd719bf061c308efdedb5f5a128c6520b3a7c37737d48a31e84b00583cc6f4222f08d1f0a636a9a87da7defe33439b1a482971a7e098692ea0c24fdc6295b55d21a60e9f6716e74448137401e3fd04e50b590f9067f918d9f0bde5b00a4aaafae86edd177252c89bb5f2470b6bc26722ee68761b22901af64aa97067ff13c7667c695018bb2b05949b9bb6c629516d208c90e9c59f8d0957464ae2ea7a6f324abe943a4fe376bcdeb0b1467ba62124a5fdc0896488ccc989ce62e76e1e5627498608808a52ccf18696b04c7b5201412a484638ad1526d6be0608a93737e625f4af84c904cdcf91de0af78ea802a9dc4c1bbc63a3871874cea6b2dead2484b10a88770d5f54ac1742efe23b008dc0fceb747b8c3180440314a6e2e190eaa22ae671c75317d2bc5399f2918a328061d7a64bf8f48963c2f4383caf5a3e400963a71948a190ce494ffedb474f585d5d6bc9941151d90977a6a26ef8315d0b4118cfe8efd5fab51d59199098fb96407ca7ed1496c3b7b699d5a30617c081a682b3c8db8c0d2bb8574148a389a10348642e1d5261bb6f433dbd359e1ed30b87ab633c10cdd4a32c5f80d702b761997fe82a22a86f0c78dc1167f30c27ca66ab70daceabebf34b4372f32f298e8c650964af4e109e0e8cf4c8e7e62d51e1d4bd021293427449df936dbdf012ab6fb8f9bcf209fee0419ac93dfaf9cb316e5c2017b91eeee2410b7f76050bfc5f55f2db4e81b4c04ffd8c87820130d566d36ac546b295bcc972b0d2d891ba7e75e9bfcdb17cd6aa4a844882e0e438930baa30b69efd3707a002cea0485985eae0425e52ea25787bafa393672b1f92d19363a57104bea6b46d13587cc4771596e46274cbe81da5b1906abe25b2279b5f7016b00a108425cc66215f408ec5ef18ad6b5f82b0d33dd22224627bdcc2a9b47587685fcf09aaebf6ed7cac173cbe824dd080f21d1e5463c1697ceaf931f54b875ef4ecb98c07f884a9cd5ffdb87d779e70bc2dce60b4dcd662a8c9287baafff452b31569ac50386fa2c9c940c165cbb6c2bad1b70df67f3ba98bfe4e71441b617b0c861fcb193b617eecc6ec3e6416c31e836b2f9ae0d9ced7d9ef409b4a256f349eec3ef5af3b36a62f1159346e62dcac4c9d732ca691043648341d16b40fc76a3f91be39a699b7fd596ca33fee4126794f9b4521a31ebc1ecb_mpz;

	if (!(millerRabinl(p) && millerRabinl(q)))
		return NULL;
	
	mpz_class phi = (p - 1) * (q - 1);

	mpz_class publicKey;
	bool pr = false;

	unsigned char buf[960];
	size_t buflen = 960;
	ssize_t len = 0;	

	while (!pr)
	{
		len = getrandom(buf, buflen, 0);
		for (int i = 0; i < 960; i++)
		{
			mpz_class tmp = buf[i];
			publicKey |= tmp << ((959 - i) * 8);
		}
		publicKey %= phi;

		if (euclGCDl(publicKey, phi) == 1)
			pr = true;
		else 
			publicKey = 0_mpz;
	}

	mpz_class privateKey = findInvl(publicKey, phi);

	mpz_class* keys = new mpz_class[3];
	keys[0] = p * q;
	keys[1] = publicKey;
	keys[2] = privateKey;

	return keys;
}