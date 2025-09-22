# Kriptografija

## K.1. Навести разлике између симетричних и асиметричних криптосистема

Simetrični:
- Postoji samo jedan privatni ključ za enkriptovanje koji koriste oba korisnika (i za dekriptovanje)
- Da bi haker mogao da pristupi podacima njemu je potreban taj privatni ključ
- Prednost - Brzina
- Mane:
    - Problem distribucije (razmene) ključa
    - Komplikovan za veliki broj korisnika
- Koristi se za šifrovanje velikih količina podataka


Asimetrični:
- Postoji par ključa, odnosno javni i privatni ključ. Javni ključ nije tajan, a privatni jeste.
- Javni ključ se koristi za enkriptovanje podataka, dok se privatni koristi za dekriptovanje.
- Prednosti:
    - Rešava problem distribucije (razmene) ključa
    - Jednostavno upravljanje ključevima
- Mana - sporost (zahteva naprednije matematičke operacije)

## K.2. Цезарова и афина шифра и њихова криптоанализа

Cezarova - f(C) = C + a (mod 26)

Afina - f(C) = aC + b (mod 26), a je uzajamno prost sa 26

Rešavanje Cezarove šifre se svodi na jednačinu sa jednom nepoznatom, dok kod afine šifre sa dve nepoznate. Kod afine se brutforsuje tako što se pretpostavlja najčešće slovo u šifratu poklapa sa najčešćim slovom u engleskom jeziku (E). Isto tako i za drugo slovo.

## K.3. Једнократна шифра (One Time Pad)

- Teoretski najsigurniji metod šifrovanja jer je matematički nemoguće razbiti ga, ako se primeni pravilno.
- Ključ i poruka se pretvore u binarne nizove i izvrši se operacija XOR. Dešifrovanje je isto.

## K.4. Матрично криптовање диграфа.

Umesto da šifrujemo slovo po slovo (kod afinih), ovde se šifruju parovi slova (digrafi) odjednom.

Ideja:
1. Poruka se podeli u parove slova
2. Svaki par se pretvori u vektor
3. Taj vektor se množi sa tajnom 2x2 matricom (ključem)
4. Dešifrovanje se vrši inverznom matricom.

## K.5. Једносмерне функције. Навести пример једносмерне функције.

Jednosmerna funkcija je matematička funkcija koju je lako izračunati u jednom smeru, ali je praktično nemoguće izračunati u suprotnom smeru.

Primer - f(a, b) = a * b, gde su a i b ogromni prosti brojevi (RSA kriptosistem).

## K.6. Дифи-Хелманов алгоритам за усаглашавање кључа.

Ovaj algoritam se zasniva na problem diskretnog logaritma.

### Korak 1: Javni dogovor

Aca i Boban se javno dogovore oko dve stvari koje svako može da vidi, pa i Cone:

- Veliki prost broj p (mod p)
- Generator g - broj između 1 i p-1 koji može da generiše sve druge brojeve u grupi

### Korak 2: Lične tajne

Sada Aca i Boban biraju svoju tajnu:

- Aca tajno izabere broj a_A i računa A = g^a_A (mod p) i pošalje samo A Bobanu. a_A ostaje tajna
- Boban tajno izabere broj a_B i računa B = g^a_B (mod p) i pošalje samo B Aci. a_B ostaje tajna

Cone sada vidi p, g, A i B, ali ne zna a_A ni a_B

### Korak 3: Stvaranje zajedničke tajne

- Aca uzima broj B koji je dobio od Bobana i stepenuje ga sa svojom tajnom a_A:
<br>
K_A = B^a_A (mod p) = (g^a_B)^a_A (mod p) = g^(a_B * a_A) (mod p)
- Boban uzima broj A koji je dobio od Ace i stepenuje ga sa svojom tajnom a_B:
<br>
K_B = A^a_B (mod p) = (g^a_A)^a_B (mod p) = g^(a_A * a_B) (mod p)

K_A = K_B

Cone ne može da izračuna ovaj ključ jer bi morao iz A da izračuna a_A, što je problem diskretnog logaritma.

## K.7. Алгоритам за степеновање поновљеним квадрирањем.

Kada vidiš izraze kao g^n, gde n može biti ogroman broj, prva pomisao bi bila da množiš g sa samim sobom n puta. To bi trajalo predugo, pogotovo sa brojevima od 200 cifara.

Ideja je da se eksponent n zapiše binarno, a zatim se izračunavaju samo potrebni stepeni broja g uzastopnim kvadriranjem (g^2, g^4, g^8, itd.). Na kraju se pomnože samo oni stepeni koji odgovaraju jedinicama u binarnom zapisu eksponenta.

Ovo smanjuje broj operacija sa n na otprilike log n, što je ogromna ušteda u vremenu.

## K.8. Дефинисати дискретни логаритам. Навести 3 криптосистема који се заснивају на проблему дискретног логаритма.

Ako imamo jednačinu a = g^n u nekoj grupi (poput F*q), najmanji prirodan broj n koji zadovoljava tu jednačinu zove se diskretni logaritam broja a sa osnovom g, i označava se sa log_g(a).

Primeri: 
1. Difi-Helmanov algoritam: Koristi se za bezbednu razmenu (usaglašavanje) ključa.
2. Mesi-Omura kriptosistem: Služi za razmenu poruka ili ključeva, gde Cone mora da reši problem diskretnog logaritma da bi otkrila tajne eksponente.
3. ElGamalov kriptosistem: Koristi se za šifrovanje poruka, a njegova sigurnost direktno zavisi od toga da Cone ne može da izračuna tajni ključ e_B iz javnog ključa g^e_B.

## K.9. Алгоритам Гељфонд-Шенкса (Baby-step-giant-step алгоритам).

Glavna ideja je "sresti se na pola puta" (meet-in-the-middle):

1. Tražimo nepoznati eksponent n u jednačini g^n = a.
2. Algoritam zapiše n u obliku mi + j, gde je m otprilike √q.
3. Jednačina g^(mi+j) = a se onda pretvara u g^j = a * (g^-m)^i.
4. Zatim, algoritam pravi dve liste:
    - "Baby steps": računa g^j za sve moguće (male) vrednosti j.
    - "Giant steps": računa a * (g^-m)^i za sve moguće (male) vrednosti i.
5. Kada nađe istu vrednost u obe liste, pronašao je par (i, j) i iz toga lako može da izračuna originalni eksponent n = mi + j.

Ovaj algoritam je razlog zašto parametri u kriptografiji (poput q - broj elemenata u konačnom polju u kojem radimo) moraju biti ogromni. Ako je q broj sa 200 cifara, onda je √q broj sa 100 cifara, što je i dalje preveliko za izračunavanje.

## K.10. Полиг-Хелманов алгоритам.

Uslov je da broj q-1 ima samo male proste faktore. Takav broj se zove "gladak".

Strategija algoritma je "podeli pa vladaj":

1. Prvo rastavi q-1 na proste faktore: q-1 = p₁^a₁ * p₂^a₂ * ...

2. Umesto da rešava jedan ogroman problem log_g(a) po modulu q-1, on ga razbija na više manjih, lakših problema, rešavajući logaritam po modulu svakog od tih malih prostih faktora (p₁^a₁, p₂^a₂, itd.).

3. Na kraju, koristi  Kinesku teoremu o ostacima da spoji rešenja tih malih problema u konačno, veliko rešenje.

Najvažnija pouka ovde je sigurnosna: Kada se bira prost broj q za kriptosistem, mora se osigurati da q-1 ima bar jedan veliki prost faktor. To čini broj q-1 "ne-glatkim" i ovaj algoritam postaje beskoristan.

## K.11. Меси-Омура криптосистем.

Ideja je sledeća:

1. Aca -> Bob: Aca stavi poruku M u kutiju i zaključa je svojim katancem e_A. Pošalje je Bobu.

2. Bob -> Aca: Bob ne može da otvori kutiju, ali može da doda svoj katanac e_B na nju. Sada kutija ima dva katanca. On je vraća Aci.

3. Aca -> Bob: Aca skida svoj katanac e_A sa kutije (jer ima ključ d_A). Na kutiji ostaje samo Bobov katanac. On ga ponovo šalje Bobu.

4. Kraj: Bob dobija kutiju sa samo svojim katancem, otključava je svojim ključem d_B i čita poruku M.

Cone je sve vreme video kutiju sa raznim katancima, ali nikada nije mogao da je otvori.

Matematički, to izgleda ovako:

1. M^(e_A)

2. (M^(e_A))^(e_B) = M^(e_A * e_B)

3. (M^(e_A * e_B))^(d_A) = M^(e_B)

4. (M^(e_B))^(d_B) = M

## K.12. Алиса шаље Бобу поруку помоћу Меси-Омура криптосистема, и претпоставимо да је Цица видела целокупну комуникацију. Објаснити зашто Цица ипак не може да декриптује поруку.

Odgovor leži direktno u problemu diskretnog logaritma.

### Šta Cica vidi?

Cica je presrela celu komunikaciju i ona ima tri šifrovane verzije poruke:

1. C₁ = M^(e_A) (prva poruka od Alise)

2. C₂ = M^(e_A * e_B) (poruka sa oba katanca, od Boba)

3. C₃ = M^(e_B) (poruka samo sa Bobovim katancem, od Alise)

Ona takođe zna javni parametar q.

### Šta Cici treba?

Da bi dobila originalnu poruku M, Cica mora da "skine" jedan od katanaca. Na primer, da bi iz poruke C₁ dobila M, ona mora da zna Alisin tajni ključ za otključavanje, d_A. Da bi izračunala d_A, ona prvo mora da zna Alisin tajni eksponent e_A.

### Zašto je to nemoguće?

Cica može da uoči vezu između poruka koje je presrela. Na primer, ona vidi da važi:
(C₃)^(e_A) = (M^(e_B))^(e_A) = M^(e_A * e_B) = C₂

Dakle, ona ima jednačinu C₂ = (C₃)^(e_A). Da bi iz ove jednačine našla nepoznati eksponent e_A, ona mora da reši problem diskretnog logaritma: e_A = log_(C₃)(C₂).

Kao što smo već utvrdili, ovaj problem je praktično nerešiv ako su brojevi dovoljno veliki. Pošto Cica ne može da otkrije ni e_A ni e_B, ne može da izračuna ni ključeve za dešifrovanje d_A i d_B, i samim tim ne može doći do originalne poruke M.

Sistem je siguran.

## K.13. ЕлГамалов криптосистем.

Ovaj sistem je direktna primena Difi-Helmanove ideje, ali ovog puta za šifrovanje poruka. To je asimetrični sistem gde Bob (primalac) ima javni ključ, a Alisa (pošiljalac) ga koristi da šifruje poruku za njega.

### 1. Bobova priprema (Generisanje ključeva)

- Bob odabere tajni ključ e_B (ceo broj). 

- Koristeći javne parametre q i g, on izračunava svoj javni ključ: h = g^(e_B). 

- Ovaj javni ključ h on objavljuje svima. Svoj tajni ključ e_B čuva samo za sebe.

### 2. Alisino šifrovanje

Alisa želi da pošalje poruku M Bobu.

- Ona generiše slučajan, jednokratni broj k. 

- Koristeći Bobov javni ključ h, ona izračunava zajedničku tajnu: s = h^k = (g^(e_B))^k.

- Ona "maskira" svoju poruku M množeći je sa zajedničkom tajnom: c = M * s.

- Alisa šalje Bobu par vrednosti: (g^k, c). 

### 3. Bobovo dešifrovanje

Bob dobija par (p, c) od Alise, gde je p = g^k.

- On uzima prvi deo para, p, i koristi svoj tajni ključ e_B da izračuna istu zajedničku tajnu: s = p^(e_B) = (g^k)^(e_B). 

- Sada kada zna tajnu s, on "skida masku" sa poruke tako što podeli c sa s (ili pomnoži sa inverzom od s). 

- Rezultat je originalna poruka: c * s⁻¹ = (M * s) * s⁻¹ = M.

Cica vidi Bobov javni ključ h, kao i par (g^k, c) koji Alisa šalje. Međutim, da bi otkrila poruku M, ona mora da zna zajedničku tajnu s. A da bi izračunala s, mora da reši problem diskretnog logaritma da bi otkrila ili Bobov tajni ključ e_B ili Alisin jednokratni ključ k.

NAPOMENA:

- q i g: Pravila igre. To su javni brojevi koje svi znaju, i Alisa, i Bob, i Cica.

- M: Poruka. Ono što Alisa želi da pošalje Bobu.

- e_B: Bobov TAJNI ključ. Broj koji samo Bob zna i nikome ga ne otkriva.

- h = g^(e_B): Bobov JAVNI ključ. To je "javni sef" koji Bob izračuna pomoću svog tajnog ključa i stavi ga na trg da ga svi vide. Svako može da ubaci poruku u ovaj sef.

- k: Alisin jednokratni TAJNI broj. Ključ koji Alisa nasumično izabere samo za ovu jednu poruku i posle ga "baci".

- s: Zajednička tajna. Magični broj koji i Alisa i Bob mogu da izračunaju (svako na svoj način), ali Cica ne može.

## K.14. Како се генерише случајан велики прост број?

Princip je sledeći:

1. Generiši: Pomoću generatora slučajnih brojeva, izabere se jedan ogroman, slučajan neparan broj n. 

2. Testiraj: Taj broj n se testira da li je prost.

3. Ponavljaj: Ako n nije prost, testira se sledeći neparan broj, n+2, pa n+4, i tako dalje, sve dok se ne nađe broj koji prođe test primarnosti. 

Ključna stvar u celom procesu je efikasan test primarnosti. Proveravanje deljenjem sa svim brojevima do √n bi trajalo vekovima za brojeve koje koristimo u kriptografiji.

## K.15. Тестови прималности. Шта су улазни и излазни подаци код теста прималности?

Ulazni podaci za test primarnosti su uvek:

1. Broj n koji želimo da testiramo.

2. Jedan ili više parametara a (koji se zovu "svedoci" ili "baze") pomoću kojih se vrši testiranje.

Većina brzih testova su probabilistički, što znači da ne daju uvek 100% siguran odgovor. Njihov rezultat je jedan od sledeća dva:

1. "n je SLOŽEN": Ovaj odgovor je 100% tačan. Ako test kaže da je broj složen, on to sigurno jeste.

2. "n je VEROVATNO PROST": Ovaj odgovor znači da broj n može biti prost, ali postoji i mala šansa da je složen broj koji je "prevario" test za tu konkretnu bazu a.

Zato se test u praksi ponavlja više puta (npr. 20-50 puta) sa različitim, nasumično izabranim bazama a. Svaki put kada broj prođe test, naša sigurnost da je on zaista prost eksponencijalno raste i postaje praktično apsolutna.

## K.16. Дефинисати псеудопросте и Кармајклове бројеве. Шта је главни недостатак Кармајкловог теста прималности?

Obe definicije su vezane za Fermatov test primarnosti, koji jednostavno proverava da li je a^(n-1) ≡ 1 (mod n).

- Pseudoprost broj (u bazi a): Ovo je složen broj n koji uspeva da "prevari" Fermatov test za jednu određenu bazu a. Na primer, 91 (što je 7 * 13) je pseudoprost za bazu 3, ali nije za bazu 2. 

- Karmajklov broj: Ovo je "ultimativni lažov". To je složen broj koji prolazi Fermatov test za svaku moguću bazu a (koja je uzajamno prosta sa njim).

Glavni nedostatak Fermatovog testa (koji se u ovom kontekstu zove i Karmajklov test) je upravo postojanje Karmajklovih brojeva. Zbog njih, ovaj test ne može da napravi razliku između pravih prostih brojeva i Karmajklovih brojeva.  Ma koliko puta ga ponovili sa različitim bazama, Karmajklov broj će uvek proći test i lažno se predstaviti kao "verovatno prost".

Zato je ovaj test, iako brz, nepouzdan i u praksi se koriste jači testovi, poput Miler-Rabinovog.

NAPOMENA: Baza je jednostavno broj a koji nasumično izaberemo da bismo izvršili test.

## K.17. Милер-Рабинов тест прималности.

On je jača i pametnija verzija Fermatovog testa.

Miler-Rabinov test ne proverava samo da li je na kraju a^(n-1) ≡ 1 (mod n). On proverava i "put" do tog rezultata.

Zasnovan je na sledećoj činjenici: u polju prostih brojeva, jedini brojevi koji na kvadrat daju 1 su 1 i -1 (tj. p-1). Ako nađemo bilo koji drugi broj x takav da je x² ≡ 1 (mod n), a da x nije ni 1 ni -1, onda broj n sigurno nije prost.

Kako test radi (uprošćeno):

- Uzmemo broj n-1 i zapišemo ga kao 2^r * d (gde je d neparno). 

- Izračunamo a^d (mod n). Ako je rezultat 1 ili -1, broj prolazi test. 

- Ako nije, kvadriramo rezultat iz prethodnog koraka ((a^d)², (a^d)⁴, itd.) do r-1 puta.

- Ako u nekom trenutku dobijemo -1, broj prolazi test. 

- Ako u nekom trenutku dobijemo 1, a prethodni rezultat nije bio -1, broj pada test jer smo našli "lažni" koren iz jedinice. 

- Ako nismo dobili ni 1 ni -1 na kraju, broj takođe pada.

Najvažnije: Ne postoje "Miler-Rabinovi Karmajkl brojevi". Ne postoji složen broj koji može da prevari ovaj test za svaku bazu.  Zato, ponavljanjem testa sa dovoljno različitih baza a, možemo biti praktično sigurni da je broj koji je prošao sve testove zaista prost.

## K.18. Веза између псеудопростих и јако псеудопростих бројева. Ефикасност Кармајкловог и Милер-Рабиновог теста.

Svaki jako pseudoprost broj u nekoj bazi a je automatski i "običan" pseudoprost broj u toj istoj bazi. Obrnuto ne važi.

Karmajklov (Fermatov) test

- Efikasnost: Za složen broj koji nije Karmajklov, verovatnoća da prođe test je najviše 1/2. Nakon k ponavljanja, verovatnoća greške je najviše (1/2)^k .

- Glavni nedostatak: Potpuno je **nemoćan protiv Karmajklovih brojeva**. Oni će uvek proći test, bez obzira na to koliko puta ga ponovili. Zbog ovoga je test nepouzdan.

Miler-Rabinov test

- Efikasnost: Verovatnoća da bilo koji složen broj prođe test je značajno manja – najviše 1/4. Nakon k ponavljanja, verovatnoća greške je najviše (1/4)^k, što mnogo brže teži nuli.

- Glavna prednost: Ne postoje apsolutni "lažovi" kao što su Karmajklovi brojevi za Fermatov test. To ga čini izuzetno pouzdanim u praksi.

Zaključak: Miler-Rabinov test je mnogo efikasniji i pouzdaniji jer je stroži, manja je verovatnoća da ga složen broj prevari, i što je najvažnije, ne postoji vrsta složenog broja koja ga uvek može prevariti.

## K.19. Ривест-Шамир-Ејделман криптосистем (РСА).

Sigurnost RSA sistema se ne zasniva na problemu diskretnog logaritma, već na problemu faktorizacije velikih brojeva (n = p * q).

Ceo proces se odvija u tri glavna dela: generisanje ključeva, šifrovanje i dešifrovanje.

### 1. Bob generiše ključeve (ovo se radi samo jednom)

- Tajni korak: Bob izabere dva ogromna, različita prosta broja, p i q, i čuva ih u najstrožoj tajnosti.

- Javni korak: Izračuna njihov proizvod n = p * q. Ovaj broj n je deo javnog ključa.

- Tajni korak: Izračuna φ(n) = (p-1)(q-1). Ovaj broj mu treba da bi napravio ključeve i takođe ga čuva u tajnosti.

- Javni korak: Izabere mali neparan broj e koji je uzajamno prost sa φ(n). Broj e je drugi deo javnog ključa.

- Tajni korak: Izračuna d, koje je inverz od e po modulu φ(n). Broj d je njegov tajni ključ za dešifrovanje.

Na kraju, Bob objavljuje svoj javni ključ (n, e), a tajni ključ d čuva samo za sebe.

### 2. Alisa šifruje poruku

Alisa želi da pošalje poruku M. Ona uzima Bobov javni ključ (n, e) i računa:

C = M^e (mod n) 

Rezultat C (šifrat) šalje Bobu.

### 3. Bob dešifruje poruku

Bob dobija C od Alise. Da bi dobio originalnu poruku M, on koristi svoj tajni ključ d:

M = C^d (mod n) 

Ovo funkcioniše jer je (M^e)^d = M^(ed) ≡ M (mod n), pošto su e i d specijalno napravljeni da budu inverzni jedan drugom po modulu φ(n).

## K.20. Привидно једносмерне функције. Навести пример привидно једносмерне функције.

Prividno jednosmerna funkcija (trapdoor one-way function) je funkcija koju je:

- Lako izračunati u jednom smeru.

- Teško je invertovati (izračunati unazad).

- ALI, postoji tajna informacija, zvana "tajna vrata" (trapdoor), pomoću koje invertovanje postaje lako.

Primer: RSA funkcija

Najbolji primer je upravo RSA funkcija šifrovanja: 

C = M^e (mod n).

- Lak smer: Za bilo koga (Alisa, Cica) je lako da uzme poruku M i javni ključ (n, e) i izračuna šifrat C.

- Težak smer: Za Cicu je praktično nemoguće da iz C, n i e izračuna originalnu poruku M. Za nju, ovo je jednosmerna funkcija.

- "Tajna vrata": Bob poseduje tajnu informaciju – proste faktore p i q od broja n. Pomoću njih, on lako može da izračuna tajni ključ d i invertuje funkciju: M = C^d (mod n). Faktorizacija broja n je "trapdoor".

## K.21. Фермаов метод факторизације.

Uslov: Dva prosta faktora, p i q, veoma blizu jedan drugom.

Metod se zasniva na predstavljanju broja n kao razlike kvadrata:

n = s² - t²

Ako uspemo da nađemo takve brojeve s i t, onda smo lako faktorisali n, jer je:

n = (s - t) * (s + t)

Tada je p = s - t, a q = s + t.

Kako naći s i t?

1. Počnemo sa najmanjim mogućim brojem s, što je prvi ceo broj veći od √n.

2. Izračunamo s² - n.

2. Proverimo da li je rezultat potpun kvadrat.

    - Ako jeste, našli smo t²! Izvadimo koren da dobijemo t i time smo otkrili faktore p i q.

    - Ako nije, povećamo s za 1 i vratimo se na korak 2.

Ako su p i q blizu, onda će t = (q-p)/2 biti malo, što znači da će s biti vrlo blizu √n, pa će algoritam brzo naći rešenje.

## K.22. Криптоанализа РСА Фермаовим методом.

Kriptoanaliza je vrlo direktna:

1. Cica uzme Bobov javni broj n i primeni na njega Fermaov metod.

2. Ako je Bob bio nepažljiv i izabrao proste brojeve p i q koji su blizu jedan drugom, Cica će veoma brzo uspeti da faktoriše n.

3. Jednom kada Cica ima p i q, ona može da izračuna tajnu vrednost φ(n) = (p-1)(q-1).

3. Sa φ(n) i javnim eksponentom e, ona lako izračunava Bobov tajni ključ d i može da dešifruje sve poruke.

Zaključak i preporuka: Prilikom generisanja ključeva za RSA, apsolutno je neophodno osigurati da izabrani prosti brojevi p i q budu nasumični i dovoljno udaljeni jedan od drugog.

## K.23. Полардов (p-1) -метод.

Ovaj metod je, kao i Fermaov, efikasan samo pod određenim uslovima. On ne zahteva da p i q budu blizu, već napada drugu potencijalnu slabost: ako broj p-1 (ili q-1) ima samo male proste faktore.

Ideja Polardovog (p-1) metoda:

1. Znamo da za prosti faktor p broja n važi a^(p-1) ≡ 1 (mod p).

2. Ako je broj p-1 "gladak", što znači da ima samo male proste faktore (npr. p-1 = 2 * 3 * 3 * 5), onda će p-1 sigurno deliti neki veliki broj m koji je proizvod svih malih brojeva (npr. m = 100!).

3. Ako p-1 deli m, onda važi i a^m ≡ 1 (mod p).

4. Ova jednakost nam govori da je a^m - 1 deljivo sa p.

5. Pošto je i n deljivo sa p, sledi da je p zajednički delilac za n i a^m - 1.

Na osnovu ovoga, Cica može da uradi sledeće:

- Izabere neku granicu za "male" faktore, B.

- Izračuna broj m koji je proizvod svih prostih brojeva manjih od B na određenom stepenu.

- Izabere nasumičnu bazu a, najčešće a=2.

- Izračuna g = NZD(n, a^m - 1).

- Ako je 1 < g < n, Cica je uspela! g je pravi delilac broja n.

Ovaj metod je veoma brz ako je Cica imala sreće i ako je Bob izabrao p takav da p-1 ima samo male proste faktore.

## K.24. Зашто се јавни кључ n=pq у РСА не може изабрати тако да не буде осетљив на напад Полардовим методом.

Problem je sledeći:

- Da bi Bob bio apsolutno siguran da njegov ključ n=pq nije ranjiv na ovaj napad, on bi morao da izabere p i q tako da brojevi p-1 i q-1 nemaju samo male proste faktore. Drugim rečima, i p-1 i q-1 moraju imati bar jedan veliki prost faktor.

- Da bi bio 100% siguran u to, Bob bi morao da potpuno faktoriše brojeve p-1 i q-1. Međutim, p i q su ogromni brojevi, pa su i p-1 i q-1 ogromni, a mi znamo da je faktorizacija teška! Time bi se vratio na problem koji pokušava da izbegne.

Bob može da testira da li je p-1 "glatko" do neke granice B (npr. do milion). Ali, uvek postoji opasnost da je p-1 glatko do granice milion i jedan, što Bob nije proverio, a Cica baš sa tom granicom može da pokuša napad.

Da bi se zaštitio od napada, Bob mora da prati sledeća pravila pri izboru prostih brojeva p i q:

1. Moraju biti ogromni i nasumično izabrani.

2. Ne smeju biti previše blizu jedan drugom (zaštita od Fermaovog metoda).

3. Brojevi p-1 i q-1 moraju imati bar jedan veliki prost faktor (zaštita od Polardovog (p-1) metoda). Ovo se u praksi postiže korišćenjem "jakih" prostih brojeva.

## K.25. Интегритет поруке и хеш алгоритам.

Integritet poruke je garancija da ono što je stiglo do Boba jeste identično onome što je Alisa poslala, bez ikakvih izmena.  Sama enkripcija ovo ne garantuje. Cica može da presretne šifrat, izmeni ga, i desi se da se on dešifruje u neku drugu, ali i dalje smislenu poruku. Bob možda ne bi ni primetio promenu.

Alat koji koristimo da osiguramo integritet je heš algoritam.

- Ulaz: Poruka bilo koje dužine (od jednog slova do celog filma).

- Izlaz: Kratak niz karaktera fiksne dužine (npr. 256 bita), koji se zove heš ili "digest".

Ovaj heš ima ključne osobine:

1. Jednosmeran je: Lako je izračunati heš poruke, ali je nemoguće iz heša rekonstruisati originalnu poruku. 

2. Otporan je na koliziju: Praktično je nemoguće naći dve različite poruke koje imaju isti heš. 

3. Deterministički je: Ista poruka će uvek dati isti heš.

4. Efekat lavine: Ako promeniš samo jedno slovo u originalnoj poruci, heš će se potpuno, drastično promeniti.

## K.26. Аутентикација, дигитални потпис и сертификат.

1. Аутентикација: Ovo je cilj. To je proces dokazivanja da je neko zaista onaj za koga se predstavlja. U našem primeru, to je način da Bob bude siguran da je poruku poslala Alisa, a ne Cica.

2. Дигитални потпис: Ovo je alat. To je kriptografski mehanizam kojim se postiže autentičnost. On matematički povezuje poruku (ili njen heš) sa javnim ključem pošiljaoca, čineći je jedinstvenom i nemogućom za falsifikovanje.

3. Сертификат: Ovo je "lična karta". Digitalni potpis povezuje poruku sa javnim ključem, ali kako znamo da taj javni ključ zaista pripada Alisi? Sertifikat je dokument koji izdaje pouzdano telo (kao MUP za lične karte) i koji kaže: "Potvrđujemo da ovaj javni ključ pripada Alisi Petrović".

Dakle, Alisa će koristiti svoj digitalni potpis da bi Bob izvršio autentikaciju njene poruke, a Bob može verovati njenom javnom ključu jer za njega postoji sertifikat.

## K.27. Дигитални потпис помоћу РСА криптосистема.

- Za šifrovanje, koristimo javni ključ da zaključamo, a privatni da otključamo.

- Za potpisivanje, koristimo privatni ključ da potpišemo, a javni ključ da proverimo potpis.

Evo kako to Alisa radi kada želi da pošalje Bobu potpisanu poruku M.

### 1. Alisino potpisivanje

1. Heširanje poruke: Prvo, Alisa uzme svoju poruku M i izračuna njen heš, h = H(M). Ovo radimo da bi potpis bio vezan za sadržaj poruke i da bi proces bio brži.

2. Kreiranje potpisa: Alisa sada uzima taj heš h i šifruje ga, ali ne Bobovim javnim ključem, već svojim privatnim ključem d_A. Rezultat je digitalni potpis S:
    
    S = h^(d_A) (mod n_A)

3. Slanje: Alisa šalje Bobu tri stvari: originalnu poruku M, svoj potpis S i svoj sertifikat (da Bob bude siguran koji je njen javni ključ).

### 2. Bobova provera

1. Heširanje poruke: Bob dobija M i S. Prvo i on izračuna heš poruke koju je dobio: h' = H(M).

2. Provera potpisa: Bob sada uzima potpis S i dešifruje ga pomoću Alisinog javnog ključa e_A:
    
    h_provereno = S^(e_A) (mod n_A)

3. Poređenje: Bob upoređuje heš koji je on izračunao (h') sa dešifrovanim potpisom (h_provereno).

Ako je h' == h_provereno, potpis je validan! Bob je sada siguran u dve stvari:

- Autentičnost: Poruka je zaista od Alise, jer je samo ona mogla da je potpiše svojim privatnim ključem.

- Integritet: Poruka nije menjana, jer se heš poklapa.

## K.28. Чему служи хеширање приликом дигиталног потписа?

Hashing služi za dve ključne stvari: brzinu i povezivanje.

### 1. Brzina i efikasnost

- Operacije sa javnim ključem (kao što je RSA potpisivanje) su veoma spore.

- Zamisli da Alisa treba da potpiše dokument od 500 strana. Kada bi morala da primeni RSA algoritam na ceo dokument, to bi moglo da potraje.

- Heš algoritmi su, s druge strane, izuzetno brzi. Oni mogu da obrade ogroman fajl i stvore kratak heš (npr. 256 bita) u deliću sekunde.

- Mnogo je brže i efikasnije potpisati taj kratki heš nego celu dugačku poruku.

2. Povezivanje potpisa sa sadržajem

- Heš je jedinstveni "otisak prsta" poruke.

- Time što Alisa potpisuje heš poruke, ona stvara potpis koji je neraskidivo vezan za tačan sadržaj te poruke.

- Ako bi neko promenio samo jedan zarez u originalnom dokumentu, heš bi se potpuno promenio, i Alisin potpis više ne bi bio validan za taj izmenjeni dokument.

- Ovo osigurava integritet – Bob je siguran da čita identičnu poruku koju je Alisa potpisala.

Ukratko, heširanje nam omogućava da napravimo brz i efikasan potpis koji je istovremeno čvrsto vezan za originalni sadržaj poruke.

## K.29. Какво побољшање доносе елиптичке криве у а) сигурности криптосистема б) криптоанализи?

### а) Poboljšanje u sigurnosti kriptosistema

Glavno poboljšanje je efikasnost: eliptičke krive (ECC - Elliptic Curve Cryptography) nude isti nivo sigurnosti kao RSA, ali sa drastično manjim ključevima.

- Sigurnost koju pruža 3072-bitni RSA ključ, ECC postiže sa ključem od samo 256 bita.

- Zašto je to važno? Manji ključevi znače brže računanje, manju potrošnju memorije i energije. Zbog ovoga je ECC idealan za uređaje sa ograničenim resursima, kao što su mobilni telefoni, pametne kartice ili IoT uređaji.

### б) Poboljšanje u kriptoanalizi

Paradoksalno, eliptičke krive ne pomažu samo u zaštiti, već daju i napadačima moćnije alate za razbijanje starijih sistema.

- Lenstrin metod faktorizacije, jedan od najmoćnijih modernih algoritama za faktorizaciju (napad na RSA), zasnovan je upravo na eliptičkim krivama.

- Zašto je bolji od Polardovog (p-1) metoda? Polardov metod radi samo ako p-1 ima male proste faktore. Lenstrin metod ima mnogo više šansi za uspeh jer on može da testira veliki broj različitih eliptičkih krivih, od kojih će za neku možda broj tačaka na njoj biti "gladak", što će mu omogućiti da faktoriše broj n.

Dakle, eliptičke krive su dvosekli mač: čine nove sisteme jačim i efikasnijim, a istovremeno pružaju alate za napad na stare.

## K.30. Дефинисати и нацртати елиптичку криву над пољем реалних бројева.

Eliptička kriva nad poljem realnih brojeva ℝ je skup svih tačaka (x, y) koje zadovoljavaju jednačinu oblika:

y² = x³ + ax + b

gde su a i b realni brojevi koji zadovoljavaju uslov da je diskriminanta Δ = -16(4a³ + 27b²) ≠ 0. Ovaj uslov je tu da osigura da kriva nema "špiceve" ili samopreseke, što je važno za operacije koje ćemo kasnije definisati.

Pored ovih tačaka, kriva uvek sadrži i jednu specijalnu, "beskonačno daleku" tačku, koju obeležavamo sa O.

<img width="454" height="338" alt="image" src="https://github.com/user-attachments/assets/4089c677-0699-4cd3-8ed2-9008fc66f57d" />

## K.31. Дефинисати елиптичку криву над коначним пољем.

Eliptička kriva nad konačnim poljem F_q (gde je q stepen prostog broja, p ≠ 2, 3) je skup tačaka E(F_q) koji se sastoji od:

1. Svih parova (x, y), gde x i y pripadaju polju F_q, koji zadovoljavaju jednačinu y² = x³ + ax + b. Sve operacije (sabiranje, množenje) se vrše unutar tog konačnog polja (npr. po modulu p).

2. Specijalne tačke u beskonačnosti, O.

Kao i ranije, koeficijenti a i b moraju da zadovolje uslov da je diskriminanta Δ ≠ 0.

Dok je nad realnim brojevima to glatka, neprekidna kriva, nad konačnim poljem to nije kriva uopšte. To je skup pojedinačnih, razbacanih tačaka čije koordinate zadovoljavaju jednačinu.

Zamisli da umesto glatke linije nacrtane na papiru, sada imaš samo šačicu zvezda na noćnom nebu. Svaka zvezda je jedna tačka na našoj "krivi".

## K.32. Дефинисати операције на елиптичкој кривој. Групни закон на елиптичкој кривој.

Da bismo "sabrali" dve tačke P i Q, uradimo sledeće:

1. Provucemo pravu liniju kroz tačke P i Q.

2. Ta linija će preseći krivu u još jednoj, trećoj tački, koju ćemo nazvati R.

3. Rezultat sabiranja, P ⊕ Q, je tačka simetrična tački R u odnosu na x-osu.

Specijalni slučajevi:

- Sabiranje tačke sa samom sobom (P ⊕ P): Umesto prave kroz dve tačke, koristimo tangentu na krivu u tački P. Ostatak procesa je isti.

- Sabiranje sa tačkom u beskonačnosti (P ⊕ O): Rezultat je uvek P. Tačka O je neutralni element, kao nula kod običnog sabiranja.

Iako je ovo geometrijska definicija, u praksi se koriste algebarske formule izvedene iz nje da bi se efikasno računalo, pogotovo u konačnim poljima.

Najvažnija posledica ove definicije sabiranja je Grupni zakon. On kaže da skup svih tačaka na eliptičkoj krivi E(F_q), zajedno sa operacijom sabiranja ⊕, formira Abelovu grupu.

To znači da ova operacija ima sve lepe osobine koje su nam potrebne za kriptografiju: zatvorena je, asocijativna, ima neutralni element (O), svaka tačka ima inverz, i komutativna je.

Zbog ovoga, možemo da radimo operaciju "množenja" tačke brojem (skalarno množenje), na primer nP = P ⊕ P ⊕ ... ⊕ P, što je direktan analog stepenovanja g^n koje smo koristili ranije.

## K.33. Хасеова теорема за број тачака на елиптичкој кривој. Зашто рад са групом (E(F_q), ⊕) нуди више могућности од групе (F_q*, ⋅)?

Haseova teorema: Broj tačaka na eliptičkoj krivi E(F_q), uključujući i tačku O, iznosi q + 1 + s, gde je s "greška" koja je uvek u intervalu |s| ≤ 2√q.

Jednostavnije rečeno, broj tačaka na krivoj je uvek veoma blizu broju elemenata u polju, q. Teorema nam daje tačan opseg u kojem se taj broj mora nalaziti.

### Zašto ECC nudi više mogućnosti?

Ovo je ključna prednost eliptičkih krivih u odnosu na "klasičnu" kriptografiju.

- "Stara" kriptografija (npr. Difi-Helman): Kada izaberemo konačno polje F_q, mi smo "zaglavljeni" sa grupom F_q*. Njena veličina (broj elemenata) je uvek q-1. Nemamo nikakav izbor. Ako se desi da je q-1 "glatki" broj (ima samo male proste faktore), naš sistem je ranjiv na Polig-Helmanov napad i tu ne možemo ništa.

- Kriptografija sa eliptičkim krivama: Za isto konačno polje F_q, mi možemo da napravimo mnogo različitih eliptičkih krivih samo menjajući koeficijente a i b u jednačini y² = x³ + ax + b.

Svaka od tih krivih će imati različit broj tačaka, ali svi ti brojevi će biti unutar opsega koji nam daje Hasseova teorema. Ovo nam daje ogromnu slobodu i izbor. Možemo jednostavno da isprobavamo različite krive sve dok ne nađemo onu čiji je broj tačaka veliki prost broj (ili ima veliki prost faktor). Takva grupa je onda otporna na Polig-Helmanov napad.

Ukratko, eliptičke krive nam daju "jelovnik" grupa, dok smo kod starijih sistema imali samo jedno, fiksno "jelo".

NAPOMENA: F_q* je oznaka za multiplikativnu grupu konačnog polja F_q. Jednostavnije rečeno, to je skup svih elemenata iz polja F_q osim nule, zajedno sa operacijom množenja.

## K.34. Проблем дискретног логаритма над елиптичким кривама.

Podsetnik (stari problem):
U grupi F_q*, ako imamo h = g^n, problem je naći n.

Novi problem (ECDLP - Elliptic Curve Discrete Logarithm Problem):
U grupi tačaka na eliptičkoj krivi E(F_q), ako imamo tačku Q koja je dobijena tako što je tačka P "sabrana" sa sobom n puta, tj. Q = nP, problem je naći broj n.

Napravimo analogiju:

- Množenje u F_q* postaje ↔ Sabiranje ⊕ na E(F_q)

- Stepenovanje g^n postaje ↔ Skalarno množenje nP

Smatra se da je problem diskretnog logaritma nad dobro izabranim eliptičkim krivama (ECDLP) značajno teži za rešavanje od problema diskretnog logaritma u grupi F_q* za grupe slične veličine.

Zbog ovoga, da bismo postigli isti nivo sigurnosti (npr. 128-bitnu sigurnost), možemo koristiti mnogo manju grupu (i samim tim mnogo manje ključeve) sa eliptičkim krivama nego sa starijim sistemima. To je razlog zašto je ECC toliko efikasan.

## K.35. Кодирање и декодирање података помоћу елиптичке криве.

Pre nego što možemo da koristimo eliptičke krive za šifrovanje poruke, moramo nekako da tu poruku (koja je u suštini broj, M) pretvorimo u tačku P(x, y) na krivoj. Ovo je proces "kodiranja".

Metod koji se koristi je probabilistički, što znači da ne uspeva uvek iz prvog puta, ali je verovatnoća uspeha izuzetno velika.

Kodiranje (Pretvaranje broja M u tačku P):

1. Priprema: Uzmemo broj M koji predstavlja našu poruku. Izaberemo i jedan mali broj k (npr. k=50), koji predstavlja maksimalan broj pokušaja.

2. Pokušaj (j=0): Pokušamo da za x-koordinatu postavimo x₀ = M*k + 0.

3. Provera: Ubacimo taj x₀ u jednačinu krive y² = x₀³ + ax₀ + b i proverimo da li desna strana jednačine ima kvadratni koren u našem konačnom polju.

4. Rezultat:

    - Ako ima rešenja, super! Uzmemo jedno rešenje za y₀ i naša kodirana poruka je tačka P = (x₀, y₀). Uspeli smo.

    - Ako nema rešenja, idemo na sledeći pokušaj (j=1). Postavimo x₀ = M*k + 1 i ponovimo korak 3.

Ovaj postupak se ponavlja (j=2, 3, ...) sve dok se ne nađe x₀ za koji jednačina ima rešenje. Pošto otprilike polovina brojeva u konačnom polju ima kvadratni koren, verovatnoća da ćemo naći rešenje u k=50 pokušaja je praktično 100%.


Dekodiranje (Pretvaranje tačke P nazad u broj M) je mnogo lakše. Kada Bob dobije tačku P(x₀, y₀) koja predstavlja poruku, on treba da uradi sledeće:

- Uzme samo x-koordinatu, x₀.

- Izračuna originalnu poruku M pomoću celobrojnog deljenja: M = x₀ // k.

Ovo radi jer je x₀ = M*k + j. Celobrojno deljenje sa k jednostavno odbaci onaj mali dodatak j koji smo koristili u pretrazi i ostavlja nam originalni M.

## K.36. Дифи-Хелманово усаглашавање кључа над елиптичким кривама.

| Korak              | Klasični Difi-Helman                           | Difi-Helman sa eliptičkim krivama (ECC)                   |
|--------------------|------------------------------------------------|-----------------------------------------------------------|
| Javni dogovor      | Svi znaju prost broj p i generator g.          | Svi znaju eliptičku krivu E i početnu tačku P na njoj.    |
| Alisina tajna      | Tajni broj a_A.                                | Tajni broj a_A.                                           |
| Alisin javni ključ | Izračuna A = g^a_A i pošalje A.                | Izračuna A_P = a_A * P i pošalje tačku A_P.               |
| Bobova tajna       | Tajni broj a_B.                                | Tajni broj a_B.                                           |
| Bobov javni ključ  | Izračuna B = g^a_B i pošalje B.                | Izračuna B_P = a_B * P i pošalje tačku B_P.               |
| Finalna tajna      | Alisa: B^a_A. Bob: A^a_B. Oboje dobiju broj K. | Alisa: a_A * B_P. Bob: a_B * A_P. Oboje dobiju tačku K_P. |

Sigurnost se zasniva na istom principu: Cica vidi početnu tačku P i javne ključeve a_A * P i a_B * P. Da bi otkrila zajedničku tajnu, ona mora da reši problem diskretnog logaritma nad eliptičkim krivama (ECDLP) da bi našla a_A ili a_B, što je, kao što smo rekli, još teži problem.

## K.37. ЕлГамалов криптосистем над елиптичким кривама.

### 1. Bobova priprema (Generisanje ključeva)

- Javni parametri: Svi znaju krivu E i početnu tačku P.

- Bobov tajni ključ: Bob izabere tajni broj e.

- Bobov javni ključ: Bob izračuna i objavi tačku H_P = e * P.

### 2. Alisino šifrovanje

Alisa želi da pošalje poruku, koju prvo kodira u tačku na krivoj, M_P.

1. Ona izabere nasumičan, jednokratni broj k.

2. Izračuna zajedničku tajnu tačku: S_P = k * H_P (koristeći Bobov javni ključ).

3. "Maskira" svoju poruku tako što je sabere sa tajnom tačkom: C_P = M_P ⊕ S_P.

4. Izračuna "trag" za Boba: P_k = k * P.

4. Alisa šalje Bobu par tačaka: (P_k, C_P).

### 3. Bobovo dešifrovanje

Bob dobija par tačaka (P_k, C_P).

1. Uzima prvu tačku P_k i množi je svojim tajnim ključem e da bi dobio istu zajedničku tajnu tačku: S_P = e * P_k = e * (k * P).

2. "Skida masku" sa poruke tako što od druge tačke C_P oduzme (sabere sa inverzom) tajnu tačku S_P: M_P = C_P ⊖ S_P.

Rezultat je originalna tačka M_P, koju Bob onda dekodira nazad u poruku. Sigurnost se, naravno, opet zasniva na teškoći ECDLP-a.

## K.38. Ленстрин метод факторизације.

On je direktno poboljšanje Polardovog (p-1) metoda.

Polardov metod radi brzo samo ako je p-1 "gladak" broj (ima male proste faktore). Ako nije, metod je beskoristan. Imamo samo jednu šansu za uspeh, koja zavisi od fiksne vrednosti p-1.

Lenstra je razmišljao: "Šta ako bismo mogli da menjamo grupu, umesto da smo zaglavljeni sa onom čija je veličina p-1?"

1. Možemo da izaberemo nasumičnu eliptičku krivu E nad poljem Z_p (iako mi ne znamo p).

2. Ta kriva će imati neki broj tačaka, N, koji je unutar Hasseovog opsega.

3. Nadamo se da je taj broj N "gladak". Ako jeste, možemo primeniti istu logiku kao kod Polardovog metoda da faktorišemo n.

4. Ključna stvar: Ako N nije "gladak", nema problema! Možemo jednostavno da izaberemo drugu, potpuno novu nasumičnu krivu E', koja će imati drugačiji broj tačaka N'. Ponavljamo ovo sve dok ne "ubodemo" krivu čiji je broj tačaka gladak.

Kako algoritam radi?

1. Cica izabere nasumičnu eliptičku krivu i tačku P na njoj.

2. Izabere granicu B i izračuna ogroman broj m (npr. B!).

3. Pokuša da izračuna m*P, radeći sve operacije sabiranja tačaka po modulu n (broj koji želi da faktoriše).

4. Očekivani ishod: U nekom trenutku tokom sabiranja tačaka, algoritam će zahtevati deljenje nekim brojem g (tj. množenje inverzom). Desiće se da g nije uzajamno prost sa n, pa inverz ne postoji i računanje puca.

5. Pobeda! U tom trenutku, NZD(g, n) će otkriti pravi faktor broja n.

Ukratko, Lenstrin metod je kao da Polardovom metodu date beskonačno mnogo šansi da uspe, jer može da proba sa hiljadama različitih krivih dok ne nađe onu "pravu".

## K.Rezime

1. Osnove i Simetrična Kriptografija

    - Simetrični vs. Asimetrični sistemi: Glavna razlika je u ključevima. Simetrični koriste jedan, deljeni tajni ključ, veoma su brzi, ali imaju problem bezbedne razmene ključa. Asimetrični koriste par ključeva (javni i privatni), rešavaju problem razmene ključa, ali su znatno sporiji. U praksi se najčešće kombinuju.
    
    - Klasične šifre: Prošli smo primere simetričnih šifara kao što su Cezarova (P+b) i afina (aP+b), koje se razbijaju frekvencijskom analizom.

    - Jednosmerne funkcije: Ovo su funkcije koje je lako izračunati u jednom smeru, a veoma teško invertovati. One su temelj svih sistema sa javnim ključem. Primer je množenje dva velika prosta broja.

2. Asimetrična Kriptografija i Diskretni Logaritam

    - Problem Diskretnog Logaritma (DLP): Ako znamo g i g^n, teško je pronaći n. Na ovom problemu se zasniva sigurnost mnogih sistema.

    - Protokoli zasnovani na DLP:

        - Difi-Helmanov algoritam: Omogućava Alisi i Bobu da preko javnog kanala dogovore zajednički tajni ključ, a da ga prisluškivač Cica ne sazna.

        - Mesi-Omura kriptosistem: Protokol za razmenu poruka u "tri koraka" gde se poruka zaključava i otključava naizmenično, bez prethodne razmene ključa. Sigurnost leži u tome što Cica ne može da izračuna tajne eksponente.

        - ElGamalov kriptosistem: Sistem za šifrovanje poruka koji koristi Difi-Helmanov princip. Alisa koristi Bobov javni ključ da napravi zajedničku tajnu i njome "maskira" poruku.

    - Alat za računanje: Stepenovanje ponovljenim kvadriranjem je brzi algoritam koji omogućava efikasno izračunavanje g^n.

3. Prosti Brojevi i Testovi Primalnosti

    - Generisanje prostih brojeva: Ne postoji formula za proste brojeve. Oni se generišu metodom "pogodi pa proveri": uzme se veliki slučajan neparan broj i testira se da li je prost. Ako nije, testira se sledeći (n+2).

    - Probabilistički testovi: Zato što je testiranje sporo, koriste se brzi, probabilistički testovi. Oni sa 100% sigurnosti mogu reći da je broj složen, ali samo sa velikom verovatnoćom mogu reći da je prost.

    - "Lažni" prosti brojevi:

        - Pseudoprosti brojevi: Složeni brojevi koji prođu prostiji, Fermatov test primarnosti za neku bazu a.

        - Karmajklovi brojevi: Složeni brojevi koji prolaze Fermatov test za svaku bazu. Oni su glavna mana ovog testa.

    - Miler-Rabinov test: Jači, pouzdaniji test koji proverava i "korene iz jedinice". Ne postoje brojevi koji ga mogu prevariti za svaku bazu, i zato je industrijski standard za proveru primarnosti.

4. RSA Kriptosistem i Faktorizacija

    - RSA algoritam: Najpoznatiji asimetrični sistem. Sigurnost se zasniva na teškoći faktorizacije velikog broja n koji je proizvod dva tajna prosta broja p i q. Javni ključ je (n, e), a tajni d. Šifrovanje je C = M^e, a dešifrovanje M = C^d.

    - Prividno jednosmerne funkcije: RSA je primer ovakve funkcije. Teško ju je invertovati, osim ako ne posedujete "tajna vrata" (trapdoor), a to je u ovom slučaju poznavanje faktora p i q.

    - Napadi na RSA: Kriptoanaliza se svodi na faktorizaciju broja n. Dva specifična napada su:

        - Fermaov metod: Efikasan ako su p i q veoma blizu jedan drugom.

        - Polardov (p-1) metod: Efikasan ako p-1 (ili q-1) ima samo male proste faktore.

5. Integritet, Autentikacija i Digitalni Potpisi

    - Integritet i Heš funkcije: Da bismo bili sigurni da poruka nije menjana, koristimo heš funkcije. One stvaraju kratak "digitalni otisak" poruke. Ako se poruka imalo promeni, heš se drastično menja.

    - Autentikacija i Digitalni potpis: Da bismo dokazali ko je poslao poruku (autentikacija), koristimo digitalni potpis. To se najčešće radi tako što se heš poruke šifruje pošiljaočevim privatnim ključem.

    - Verifikacija i Sertifikati: Bilo ko može da proveri potpis tako što ga dešifruje pošiljaočevim javnim ključem i uporedi sa hešom poruke. 

    - Sertifikati su "lične karte" koje izdaje pouzdano telo i koje garantuju da određeni javni ključ pripada određenoj osobi.

6. Kriptografija sa Eliptičkim Krivama (ECC)

    - Glavna prednost: ECC pruža isti nivo sigurnosti kao RSA, ali sa mnogo manjim ključevima, što ga čini bržim i efikasnijim, pogotovo za mobilne uređaje.

    - Osnovni koncepti: Umesto sa brojevima u F_q*, radi se sa tačkama na eliptičkoj krivi nad konačnim poljem. Operacija nije množenje, već specifično "sabiranje" tačaka (⊕).

    - ECDLP: Sigurnost se zasniva na problemu diskretnog logaritma na eliptičkim krivama (za date tačke P i Q = nP, naći n), koji se smatra još težim od klasičnog DLP-a.

    - Primene: Svi protokoli zasnovani na DLP (Difi-Helman, ElGamal) imaju svoje direktne, efikasnije verzije na eliptičkim krivama.

    - Kriptoanaliza: ECC takođe daje nove alate za napad na RSA, kao što je Lenstrin metod faktorizacije.

## K.Zadaci

### 1. Алиса и Бобан користе Дифи-Хелманов криптосистем са параметрима p=29 и g=2 (2 је генератор Z₂₉).

a) Ако је Алисин тајни кључ 12 одредити њен јавни кључ.

A = 2^12 (mod 29) = 2^5 * 2^5 * 2^2 (mod 29) = 7

б) Бобан је изабрао јавни кључ 5. Приказати како се рачуна усаглашени кључ.

K = 5^12 (mod 29) = (5^3)^4 (mod 29) = 9^4 (mod 29) = 23 * 23 (mod 29) = 7

### 2. Одредити све тачке елиптичке криве y² = x³ + x + 3 над пољем Z₇.

Moguće vrednosti za y^2 su {0, 1, 2, 3, 4}

Za x = 0:
y² = 0³ + 0 + 3 = 3. Vrednost 3 nije u skupu {0, 1, 2, 4}, tako da nema tačaka.

Za x = 1:
y² = 1³ + 1 + 3 = 5. Vrednost 5 nije u skupu {0, 1, 2, 4}, tako da nema tačaka.

Za x = 2:
y² = 2³ + 2 + 3 = 8 + 5 = 13 ≡ 6 (mod 7). Vrednost 6 nije u skupu {0, 1, 2, 4}, tako da nema tačaka.

Za x = 3:
y² = 3³ + 3 + 3 = 27 + 6 = 33 ≡ 5 (mod 7). Vrednost 5 nije u skupu {0, 1, 2, 4}, tako da nema tačaka.

Za x = 4:
y² = 4³ + 4 + 3 = 64 + 7 = 71 ≡ 1 (mod 7). Vrednost 1 jeste u skupu. Sada tražimo y:

- Ako je y² = 1, onda je y = 1 ili y = 6.

- Dobijamo tačke: (4, 1) i (4, 6).

Za x = 5:
y² = 5³ + 5 + 3 = 125 + 8 = 133 ≡ 0 (mod 7). Vrednost 0 jeste u skupu. Sada tražimo y:

- Ako je y² = 0, onda je y = 0.

- Dobijamo tačku: (5, 0).

Za x = 6:
y² = 6³ + 6 + 3 = 216 + 9 = 225 ≡ 1 (mod 7). Vrednost 1 jeste u skupu. Sada tražimo y:

- Ako je y² = 1, onda je y = 1 ili y = 6.

- Dobijamo tačke: (6, 1) i (6, 6).

Rešenje: { O, (4, 1), (4, 6), (5, 0), (6, 1), (6, 6) }

# ZKP

## ZKP.1. Zero Knowledge proofs i ilustrativni primeri.

Zero-Knowledge Proof (ZKP) je kriptografski metod gde ti, kao Dokazivač (Prover), možeš ubediti nekog drugog, Verifikatora (Verifier), da znaš neku tajnu informaciju, a da mu pritom ne otkriješ apsolutno ništa o toj informaciji. Suština je dokazati posedovanje znanja, a ne otkriti ga.

U svakoj ZKP interakciji imamo dve strane:

- Dokazivač (Prover): Strana koja poseduje tajnu informaciju i želi da dokaže njeno posedovanje.

- Verifikator (Verifier): Strana koja želi da proveri da li Dokazivač zaista poseduje informaciju, ali ne sme da sazna ništa o samoj informaciji.

### Ilustrativni Primer: Gde je Valdo? (Where is Waldo?)

Zamisli da imaš sliku "Gde je Valdo?" i pronašao si ga. Tvoj prijatelj (Verifikator) ti ne veruje. Kako možeš da mu dokažeš da znaš gde je Valdo, a da mu ne pokažeš prstom i time otkriješ lokaciju?

Rešenje sa ZKP logikom:

1. Uzeo bi ogroman karton, veći od same slike.

2. Na kartonu bi izrezao malu rupu, taman toliku da se kroz nju vidi samo Valdo.

3. Postavio bi karton preko slike tako da se Valdo vidi kroz rupu.

Rezultat: Tvoj prijatelj vidi Valda kroz rupu i uveren je da znaš gde se on nalazi. Međutim, pošto je ostatak slike pokriven kartonom, on i dalje nema pojma o Valdovoj tačnoj lokaciji na slici. Ti si dokazao svoje znanje sa nula otkrivenih dodatnih informacija.

### Ilustrativni Primer: Ali Babina pećina

Ovaj primer savršeno objašnjava kako funkcioniše interaktivni ZKP. Zamisli sledeću situaciju:

- Pećina: Imamo pećinu u obliku prstena sa jednim ulazom i magičnim vratima koja spajaju dva puta unutra, put A i put B. Vrata se mogu otvoriti samo izgovaranjem tajne fraze. 

- Akteri: Pera (Dokazivač) tvrdi da zna tajnu frazu, dok Vera (Verifikator) želi da se uveri u to.

Cilj: Pera mora da dokaže Veri da zna frazu, ali ne sme da joj otkrije frazu.

Proces dokazivanja:

1. Korak 1 (Obavezivanje - Commitment): Pera ulazi sam u pećinu. Vera ostaje napolju i ne vidi da li je Pera krenuo putem A или putem B. Recimo da Pera ode do magičnih vrata putem A.

2. Korak 2 (Izazov - Challenge): Vera prilazi ulazu u pećinu i nasumično uzvikne na koji put želi da Pera izađe. Na primer, vikne: "Izađi na put B!"

3. Korak 3 (Odgovor - Response): Pera čuje Veru i pojavljuje se na izlazu B.

Kako je Pera ovo uspeo?

- Ako Pera ZNA tajnu frazu: Nije mu bitno koji put je Vera izabrala. Ako je već na putu B, samo će izaći. Ako je na putu A (kao u našem primeru), on će iskoristiti tajnu frazu da otvori magična vrata, pređe na put B i izađe. Za Veru, on se uvek magično pojavljuje na traženoj strani.

- Ako Pera NE ZNA tajnu frazu: On ima problem. Kada uđe u pećinu, mora da se kocka i izabere jedan put, recimo A. Ako Vera uzvikne "Izađi na put A!", ima sreće. Ali ako uzvikne "Izađi na put B!", Pera je zarobljen i ne može da prođe. Njegova šansa da pogodi je samo 50%.

Ponavljanje smanjuje verovatnoću varanja: Slažeš se da 50% šanse za varanje nije baš sigurno? Zato Vera i Pera ponavljaju ovaj proces više puta.

- Nakon 2 ponavljanja, šansa da Pera vara je 25% (1/4).

- Nakon 10 ponavljanja, šansa je oko 0.1%.

- Nakon 20 ponavljanja, šansa je manja od jedan u milion!

Tako Vera, nakon dovoljnog broja ponavljanja, može biti praktično sigurna da Pera zna tajnu, iako je nikada nije čula.

Ako Verin izbor nije nasumičan, Pera bi mogao da je prevari.

### Ilustrativni Primer: Prijatelj daltonista

Zamisli da imaš prijatelja koji ne razlikuje boje (daltonista) i ti želiš da mu dokažeš da su dve loptice, jedna crvena i jedna zelena, zaista različitih boja. Za njega, one izgledaju potpuno isto.

Cilj: Da dokažeš da su loptice različite, a da mu ne otkriješ koja je crvena, a koja zelena (što on ionako ne bi razumeo).

Proces dokazivanja:

1. Korak 1: Tvoj prijatelj (Verifikator) uzima jednu lopticu u levu, a drugu u desnu ruku. Ti (Dokazivač) ih pogledaš i zapamtiš koja je gde.

2. Korak 2: Prijatelj stavlja ruke iza leđa. Iza leđa, on nasumično odlučuje da li će zameniti loptice u rukama ili će ih ostaviti kako jesu.

3. Korak 3: Prijatelj ti ponovo pokaže ruke sa lopticama.

4. Korak 4: Tvoj zadatak je da kažeš da li je zamenio loptice ili nije.

Analiza:

- Ako su loptice zaista različitih boja: Pošto ti vidiš boje, odmah ćeš znati da li je crvena loptica sada u drugoj ruci. Bićeš u pravu svaki put.

- Ako su loptice iste boje (i ti lažeš): Pošto su loptice identične, nemaš apsolutno nikakav način da znaš da li ih je zamenio. Možeš samo da nagađaš. Šansa da pogodiš je tačno 50%.

Kao i u primeru sa pećinom, ako ponovite ovo 20 puta i ti svaki put tačno odgovoriš, tvoj prijatelj će biti statistički ubeđen da loptice zaista jesu različite, iako on sam tu razliku nikada ne može da vidi.

## ZKP.2. Primene ZKP-a (Zero-Knowledge Proofs).

U suštini, ZKP je ključan svuda gde je potrebna privatnost, skalabilnost i sigurnost.

Primene:

- Blockchain (za privatnost i skaliranje) 

- Finansije 

- Online glasanje 

- Decentralizovani identiteti (DIDs) 

- Autentifikacija 

- Mašinsko učenje 

Ovo su sve oblasti gde često želimo da dokažemo nešto (npr. "imam dovoljno novca na računu", "imam pravo glasa", "ja sam ja") bez otkrivanja svih detalja.

## ZKP.3. Merkle tree i ZK dokaz pripadnosti skupu.

Merkle stablo je struktura podataka u obliku drveta gde je svaki "list" (leaf node) heš (hash) jednog bloka podataka, a svaki čvor koji nije list (non-leaf node) je heš heševa svoje dece. Vrhovni čvor, poznat kao Merkle Root, je jedan heš koji jedinstveno predstavlja ceo skup podataka. Ako se ijedan podatak u listovima promeni, Merkle Root će se takođe promeniti. Zbog ovoga se koristi za efikasnu proveru integriteta podataka.

### Kako se koristi za ZK dokaz pripadnosti skupu?

Proces funkcioniše ovako:

1. Dokaz (Merkle Path): Da bi dokazao članstvo, ti ne otkrivaš svoj list, već pružaš samo heševe "braće" (siblings) na putanji od tvog lista do vrha stabla. Ovo se zove Merkle putanja (Merkle path).

2. Verifikacija: Verifikator uzima tvoju putanju i javni Merkle Root. Korišćenjem ZK-dokaza, verifikuje se da, kada se heš tvog tajnog lista spoji sa heševima iz Merkle putanje, na kraju se zaista dobija javni Merkle Root te grupe.

3. Zero-Knowledge: Verifikator na kraju zna da ti JESI član grupe, ali nema informaciju o tome KOJI si član, jer nikada nije video tvoj originalni tajni podatak (list).

### Šta mi zapravo ovde proveravamo?

Da li tajni list, za koji tvrdiš da ga znaš, zaista jeste jedan od listova koji su korišćeni za kreiranje tog javnog Merkle Root-a.

Evo šta se dešava:

1. Dokazivač (ti) znaš svoj tajni list i Merkle putanju.

2. Ti ne šalješ verifikatoru svoj list i putanju da on "peške" računa.

3. Umesto toga, ti koristiš svoj tajni list i putanju kao privatne ulaze (private inputs) da bi kreirao ZK-dokaz (npr. ZK-SNARK).

Zamisli taj ZK-dokaz kao jednu magičnu crnu kutiju.

- Unutar kutije je "ugrađen" ceo proces provere: "Uzmi ovaj tajni list, heširaj ga sa prvim bratom, pa rezultat sa drugim, i tako sve do vrha."

- Kutija na kraju proverava da li je rezultat jednak javnom Merkle Root-u.

- Ako jeste, kutija "zasvetli zeleno" (dokaz je validan). Ako nije, "svetli crveno" (dokaz je nevalidan).

Verifikator dobija samo crnu kutiju (ZK-dokaz) i vidi da ona svetli zeleno. On nema uvid u to šta se dešava unutra. Sama matematika ZKP-a mu garantuje: "Ova kutija može da zasvetli zeleno samo ako je osoba koja ju je napravila zaista koristila validan list i putanju koji vode do poznatog Merkle Root-a."

Dakle, verifikator ne kreće ni od jednog lista. On samo proverava validnost dokaza koji mu je dat. Sam dokaz u sebi sadrži potvrdu da je putanja ispravna, bez otkrivanja same putanje ili lista.

## ZKP.4. Completeness, soundness and ZK (Potpunost, Ispravnost i Nulto Znanje)

Completeness (Potpunost)

- Šta je to? Ako je izjava koju dokazivač tvrdi istinita, i ako su i dokazivač i verifikator pošteni (prate protokol), verifikator će se uvek uveriti u dokaz.

- Jednostavnije: Ako je sve po pravilima i istinito, dokaz mora da prođe.

Soundness (Ispravnost)

- Šta je to? Ako je izjava koju dokazivač tvrdi lažna, skoro je nemoguće za lažljivog dokazivača da ubedi verifikatora da je izjava tačna. Postoji samo zanemarljivo mala verovatnoća da će lažni dokaz biti prihvaćen.

- Jednostavnije: Ako neko laže, sistem će ga (skoro sigurno) uhvatiti. Lažni dokaz ne može proći.

Zero-Knowledge (Nulto Znanje)

- Šta je to? Ako je izjava istinita, verifikator ne saznaje ništa više osim same činjenice da je izjava istinita. Bilo kakva tajna informacija (svedok, "witness") koju dokazivač koristi ostaje potpuno skrivena.

- Jednostavnije: Verifikator zna da je tačno, ali ne zna zašto je tačno.

## ZKP.5. Ciklična grupa (Zp∗​,⋅)

Zp∗​ je skup svih celih brojeva od 1 do p-1, gde je p prost broj. Na primer, 
Z11∗​ je skup {1,2,3,4,5,6,7,8,9,10}. 

Koja je operacija (⋅)? Operacija je množenje po modulu p. To znači da pomnožimo dva broja iz skupa, a zatim uzmemo ostatak pri deljenju sa p.  Na primer, u grupi Z11∗​, operacija 7⋅5 bi bila 35 (mod 11) = 2.

Ovaj skup sa ovom operacijom čini grupu, jer ispunjava četiri osnovna svojstva: zatvorenost, asocijativnost, postojanje neutralnog elementa (broj 1) i postojanje inverznog elementa za svaki element.

### Šta znači da je grupa "Ciklična"?

Grupa je ciklična ako postoji barem jedan element u njoj, koji zovemo generator (g), čijim uzastopnim stepenovanjem možemo da generišemo sve ostale elemente u grupi.

Važno je znati da je grupa (Zp∗​,⋅) uvek ciklična kada je p prost broj.

## ZKP.6. Problem diskretnog logaritma (DLP - Discrete Logarithm Problem)

On se zasniva na jednoj ključnoj činjenici: neke operacije je lako uraditi u jednom smeru, ali ekstremno teško u suprotnom.

### Jednostavan smer (Lako): Stepenovanje

Ako ti dam generator g, prost broj p i neki tajni broj x, ti možeš vrlo brzo i lako da izračunaš rezultat b:

b = g^x (mod p)

Ovo se zove modularno stepenovanje i kompjuteri to rade efikasno, čak i sa ogromnim brojevima.

### Težak smer (Problem): Diskretni logaritam

Ali, šta ako uradimo obrnuto? Dam ti javne brojeve g, p i rezultat b, a tvoj zadatak je da pronađeš tajni broj x?
Pronaći x takvo da je g^x ≡ b (mod p) se zove rešavanje problema diskretnog logaritma.

Formalno zapisano:

log_g​b = x ⟺ g^x = b u Zp∗​ 

### Zašto je ovo teško?

Za male brojeve, kao u našem primeru sa Z11∗​, možemo probati sve mogućnosti dok ne nađemo rešenje. Ali, kada je p ogroman prost broj (sa stotinama cifara), ne postoji poznat efikasan algoritam koji može da reši ovaj problem.  Trebale bi hiljade godina čak i najjačim superkompjuterima.

Analogy: Zamisli da je lako pomešati dve boje (npr. žutu i plavu) da dobiješ tačnu nijansu zelene. Ali ako ti dam samo kofu te zelene boje, skoro je nemoguće da odrediš tačan procenat žute i plave koji je korišćen.

Upravo ta "jednosmernost" čini DLP savršenim za kriptografiju. Tvoj tajni ključ je x, a javni ključ može biti b = g^x mod p. Svi mogu da vide tvoj javni ključ b, ali ne mogu da izračunaju tvoj tajni ključ x.

## ZKP.7. Eliptičke krive nad konačnim poljem.

Eliptička kriva je kriva definisana specifičnom jednačinom. U kriptografiji, ne posmatramo je nad realnim brojevima (gde bi izgledala kao glatka, neprekidna linija), već nad konačnim poljem. To znači da se kriva sastoji od konačnog broja diskretnih tačaka čije koordinate (x,y) zadovoljavaju jednačinu.

Osnovna jednačina eliptičke krive, poznata kao kratka Weierstrassova jednačina, jeste:

E: y^2 = x^3 + ax + b

Najvažnija osobina eliptičkih krivih je da sve tačke na krivoj, zajedno sa specijalnom tačkom zvanom "tačka u beskonačnosti" (oznaka O), čine Abelovu grupu. To znači da imamo definisanu operaciju "sabiranja" tačaka: ako uzmemo bilo koje dve tačke sa krive, P i Q, možemo ih "sabrati" da dobijemo treću tačku R, koja se takođe nalazi na krivoj. 

Da bismo "sabrali" dve tačke P i Q, uradimo sledeće:

1. Provucemo pravu liniju kroz tačke P i Q.

2. Ta linija će preseći krivu u još jednoj, trećoj tački, koju ćemo nazvati R.

3. Rezultat sabiranja, P ⊕ Q, je tačka simetrična tački R u odnosu na x-osu.

Specijalni slučajevi:

- Sabiranje tačke sa samom sobom (P ⊕ P): Umesto prave kroz dve tačke, koristimo tangentu na krivu u tački P. Ostatak procesa je isti.

- Sabiranje sa tačkom u beskonačnosti (P ⊕ O): Rezultat je uvek P. Tačka O je neutralni element, kao nula kod običnog sabiranja.

## ZKP.8. Add and Double algoritam.

Algoritam:

1. Predstavi skalar m u binarnom obliku. Na primer, ako želimo da izračunamo 13⋅P, binarni oblik broja 13 je 1101.

2. Kreni od najznačajnijeg bita (s leva na desno).

3. Za svaki bit u binarnom zapisu:

    - Uvek uradi "Double": Dupliraj trenutni rezultat.

    - Ako je bit 1, onda uradi i "Add": Dodaj originalnu tačku P na rezultat.

Primer: Računanje 13⋅P (1101 binarno)

- Počinjemo sa prvim bitom 1. Naš početni rezultat je P.

- Sledeći bit je 1:

    - Double: Dupliramo trenutni rezultat: 2⋅P=2P.

    - Add: Pošto je bit 1, dodajemo P: 2P+P=3P. (Trenutni rezultat je 3P)

- Sledeći bit je 0:

    - Double: Dupliramo trenutni rezultat: 2⋅3P=6P.

    - Bit je 0, tako da ne radimo "Add". (Trenutni rezultat je 6P)

- Poslednji bit je 1:

    - Double: Dupliramo trenutni rezultat: 2⋅6P=12P.

    - Add: Pošto je bit 1, dodajemo P: 12P+P=13P.

Krajnji rezultat: 13P.

Umesto 12 sabiranja, uradili smo samo 3 dupliranja i 2 sabiranja. Za velike brojeve, ova ušteda je ogromna, čineći operaciju izvodljivom u praksi.

## ZKP.9. Multi-Scalar-Multiplication (MSM) i bucket metod.

Dok je "Add and Double" algoritam za računanje jednog skalara sa jednom tačkom (m⋅P), MSM je problem efikasnog računanja sume proizvoda više različitih skalara sa više različitih tačaka:

[a1​]G1​+[a2​]G2​+[a3​]G3​+⋯+[an​]Gn​ 

Ova operacija je srce skoro svakog ZK-SNARK sistema i predstavlja najveći deo posla prilikom generisanja dokaza. Naivni pristup (računanje svakog člana posebno, pa sabiranje) je prespor kada je n ogroman (često u milionima).

### Bucket metod (Pippengerov algoritam)

Korak 1: Podela skalara (Windowing)

- Svaki veliki skalar (npr. 256-bitni) se isecka na manje delove fiksne veličine c (npr. 16 bita).

- Tako umesto jednog velikog MSM problema, dobijamo više manjih problema, gde su skalari mali brojevi (od 0 do 2c−1).

Korak 2: Punjenje "kofica" (Bucketing)

- Za svaki manji problem, napravimo 

- 2c−1 praznih "kofica" (engl. buckets), gde svaka kofica predstavlja jedan od mogućih malih skalara (1, 2, 3, ...).

- Zatim prolazimo kroz sve tačke (G1​,G2​,…). Ako je mali skalar za tačku Gi​ jednak k, onda tačku Gi​ dodamo u koficu broj k.

- Na kraju, svaka kofica sadrži zbir svih tačaka koje su imale isti mali skalar.

Korak 3: Kombinovanje

- Prvo, za svaki manji problem, saberemo sve kofice na efikasan način da dobijemo parcijalni rezultat (npr. 1⋅S1​+2⋅S2​+…, gde je Sk​ suma u kofici k).

- Na kraju, sve te parcijalne rezultate iz svih manjih problema iskombinujemo (slično kao u Add and Double, ali sa većim "pomerajima") da dobijemo konačno rešenje.

Ovaj metod je mnogo brži jer umesto mnogo skupih množenja skalarom, radi uglavnom jeftinija sabiranja tačaka u koficama.

## ZKP.10. Problem diskretnog logaritma nad eliptičkim krivama (ECDLP).

### Jednostavan smer (Lako): Množenje skalarom

Ako ti dam početnu tačku P (generator) i tajni broj m, ti možeš vrlo brzo da izračunaš krajnju tačku Q koristeći "Add and Double" algoritam:

Q=m⋅P

### Težak smer (Problem): ECDLP

Ali, ako ti dam javno poznatu početnu tačku P i krajnju tačku Q, tvoj zadatak je da pronađeš tajni skalar m. 

Pronalaženje broja m tako da važi Q=m⋅P je poznato kao Problem diskretnog logaritma nad eliptičkim krivama (ECDLP).

Operacija množenja tačke skalarom (m⋅P) na eliptičkoj krivoj je analogna operaciji stepenovanja (g^m) u klasičnim cikličnim grupama.  U oba slučaja, problem je pronaći "eksponent" (skalar m).

ECDLP se smatra značajno težim problemom od klasičnog DLP-a za ključeve iste veličine.

To znači da možemo da postignemo isti nivo sigurnosti koristeći mnogo manje brojeve. Na primer, eliptička kriva definisana nad 160-bitnim poljem nudi sigurnost uporedivu sa klasičnim DLP-om koji koristi 1248-bitne brojeve.  Manji brojevi znače brže računanje, manje memorije i bržu komunikaciju, što je razlog zašto je kriptografija bazirana na eliptičkim krivama danas dominantna.

## ZKP.11. Uparivanje na eliptičkim krivama (Pairings).

Uparivanje je specijalna matematička funkcija (mapa) koja uzima dva ulaza iz grupa eliptičke krive i daje jedan izlaz u drugoj vrsti grupe. 

Formalno, to je mapa e: G₁ x G₂ -> G_T, gde:

- G₁ i G₂ su grupe tačaka na eliptičkoj krivoj (gde je operacija sabiranje). 

- G_T je "ciljna" grupa, gde je operacija množenje. 

Zamisli to kao "most" koji povezuje svet sabiranja tačaka na krivoj sa svetom množenja brojeva.

Najvažnija osobina uparivanja je bilinearnost. To znači da se sabiranje "unutar" uparivanja pretvara u množenje "izvan" njega. 

Iz ovoga sledi najkorisnija osobina za kriptografiju:

e(a⋅P,b⋅Q)=e(P,Q)^ab 

Ovo je "supermoć" uparivanja. Omogućava nam da proveravamo jednačine sa množenjem (kao što je a⋅b=c) tako što radimo operacije sa tačkama eliptičke krive. Umesto da množimo tajne skalare a i b, mi možemo da uradimo uparivanje na javnim tačkama aP i bQ, i proverimo da li rezultat odgovara $e(P, Q)^c$. Ovo je temelj provera u mnogim ZK-SNARK sistemima.

Postoje tri glavna tipa, zavisno od odnosa između grupa G₁ i G₂:

- Tip 1 (Simetrično): Grupe su iste, G₁ = G₂. 

- Tip 2 (Asimetrično): Grupe su različite, ali postoji efikasan način da se pređe iz G₂ u G₁. 

- Tip 3 (Asimetrično): Grupe su različite i ne postoji efikasan način za prelazak između njih.  Ovaj tip se često koristi u modernim ZKP sistemima jer nudi dobru ravnotežu između performansi i sigurnosti.

## ZKP.12. STARKS & SNARKS.

SNARK je skraćenica za Succinct Non-Interactive Argument of Knowledge (Sažeti Neinteraktivni Argument Znanja).

Ključne osobine:

- Succinct (Sažet): Dokazi su izuzetno mali, često svega par stotina bajtova. Verifikacija je ekstremno brza, traje svega par milisekundi.

- Trusted Setup: Većina SNARK sistema (kao što su Groth16 i PLONK) zahteva "trusted setup" ceremoniju. To je proces koji se jednom izvrši da bi se generisali javni parametri. Sigurnost sistema zavisi od toga da se "toksični otpad" (tajni podaci) iz ove ceremonije uništi, jer bi onaj ko ga poseduje mogao da lažira dokaze.

STARK je skraćenica za Scalable Transparent Arguments of Knowledge (Skalabilni Transparentni Argumenti Znanja).

Ključne osobine:

- Scalable (Skalabilan): Vreme potrebno za kreiranje dokaza raste veoma efikasno (skoro linearno) sa složenošću problema.

- Transparent (Transparentan): Ovo je najveća prednost. STARK-ovi ne zahtevaju trusted setup. Svi parametri se generišu iz javno dostupne, proverljive nasumičnosti. Zbog ovoga se smatraju transparentnim.

- Kvantna otpornost: Zasnovani su na heš funkcijama otpornim na koliziju, što ih čini teorijski otpornim na napade kvantnih kompjutera, za razliku od SNARK-ova koji se oslanjaju на uparivanja.

Zaključak: Ne postoji "bolji" sistem, već se bira onaj koji više odgovara konkretnoj primeni. Ako je veličina dokaza najbitnija (npr. za blockchain transakcije), SNARK je bolji. Ako je transparentnost i otpornost na kvantne kompjutere prioritet, STARK je bolji izbor.

## ZKP.13. Aritmetizacija i sistem ogrančenja (system constraints).

Aritmetizacija je proces prevođenja nekog kompjuterskog programa ili izjave u jezik matematike koji ZKP sistemi razumeju — konkretno, u skup polinomskih jednačina.

Kako to radimo? Pomoću Sistema Ograničenja.

Svaki složen proračun se prvo razbije na niz osnovnih operacija, kao što su x * y = z ili x + y = z. Ovaj niz operacija zovemo aritmetičko kolo (arithmetic circuit).

Zatim, za to kolo, definišemo sistem ograničenja (system of constraints). To je skup jednačina koje moraju biti zadovoljene da bi proračun bio tačan. Postoje dve glavne vrste ograničenja, kao što vidimo u primeru iz tvojih materijala za izjavu: "Znam a tako da je a^2 + 1 = b".

1. Ograničenja Kapija (Gate Constraints): Opisuju logiku svake pojedinačne operacije.

    - Za množenje $a⋅a=o_1$​: jednačina je $a⋅a−o_1​=0$.

    - Za sabiranje $o_1​+1=b$: jednačina je $o_1​+1−b=0$.

2. Ograničenja Kopiranja (Copy Constraints): Osiguravaju da su "žice" između operacija ispravno povezane.

    - U našem primeru, izlaz iz množenja ($o_1$​) mora biti ulaz u sabiranje. Dakle, imamo ograničenje koje kaže da te dve vrednosti moraju biti jednake.

Zaključak: Kada sve ovo povežemo, dobijemo sistem ograničenja — listu jednačina. Ako Dokazivač (Prover) uspe da pronađe vrednosti za sve promenljive (a, o_1, b) koje zadovoljavaju sve jednačine istovremeno, to je matematički dokaz da je originalni proračun (a^2 + 1 = b) bio ispravan. Tajni brojevi koje samo dokazivač zna (u ovom slučaju a i o_1) se nazivaju svedok (witness).

## ZKP.14. Komitmenti pomoću polinoma (Polynomial Commitments) kod SNARK-ova.

Ideja je da se cela lista tajnih vrednosti (svedok) pretvori u jedan jedini matematički objekat — polinom. Sada, umesto da dokazuje da zna dugačku listu brojeva, Dokazivač treba da dokaže da zna taj jedan polinom.

PODSETNIK: Svedok (Witness): Da bi dokazao da je program ispravno izvršen, Dokazivač (Prover) mora da pokaže da zna tajne vrednosti (svedoka) koje zadovoljavaju sve te jednačine.

Polinomski komitment je kratak, kriptografski "otisak prsta" (fingerprint) tog polinoma. To je proces gde se Dokazivač "obavezuje" (commits) na jedan specifičan polinom, a da ga pritom ne otkriva.

Ovaj "otisak" mora da ima dva ključna svojstva:

1. Binding (Obavezujuće): Jednom kada se obavežeš na jedan polinom, ne možeš se kasnije predomisliti i tvrditi da je tvoj "otisak" došao od nekog drugog polinoma. Vezan si za svoj izbor.

2. Hiding (Skrivajuće): Sam "otisak" (komitment) ne otkriva apsolutno ništa o polinomu od kojeg je nastao.

Analogija:

- Polinom/Svedok: Zamisli da Naruto ima ogroman, tajni svitak sa zabranjenom tehnikom. Taj svitak je naš polinom.

- Dokazivač (Prover): Naruto želi da dokaže Kakashiju da poseduje originalni svitak.

- Verifikator (Verifier): Kakashi želi da se uveri, ali Naruto ne sme da mu pokaže ceo svitak.

- Komitment: Naruto koristi specijalnu tehniku pečaćenja (to je šema komitmenta) i na mali, prazan papir stvara jedinstveni pečat (to je komitment). Taj pečat je obavezujući (samo originalni svitak može da stvori taj pečat) i skrivajući (gledajući u pečat, Kakashi ne saznaje ništa o tehnici u svitku). Naruto daje taj papir sa pečatom Kakashiju.

- Provera: Kakashi onda kaže: "U redu, ako imaš pravi svitak, reci mi koja je 10. reč na 5. strani." Naruto pogleda u svoj svitak, kaže reč, i uz to napravi i mali ZK-dokaz koji potvrđuje da ta reč zaista potiče iz svitka koji odgovara pečatu. Kakashi proverom dokaza biva ubeđen da Naruto ima pravi svitak, iako ga nikad nije video.

## ZKP.15. Trusted setups kod Groth 16 i PLONK-a.

Trusted Setup (ceremonija poverenja) je procedura koja se izvrši jednom pre nego što ZKP sistem počne da se koristi, kako bi se generisali javni parametri (zovu se i CRS - Common Reference String) koje će svi kasnije koristiti za kreiranje i proveru dokaza.

Procedura počinje sa tajnim, nasumičnim brojem (nazovimo ga s). Koristeći s, generišu se javni parametri, npr. $[G,sG,s_2G,s_3G,…]$. Nakon što se parametri naprave, tajni broj s mora biti uništen. 

Problem je: ako osoba koja je generisala parametre sačuva tajnu s (koju zovemo "toksični otpad"), ona može da kreira lažne dokaze koji će izgledati validno! Zato se ceremonija radi sa više učesnika, gde svako dodaje svoju tajnu, pod pretpostavkom da će bar jedan od njih biti pošten i uništiti svoj deo tajne. 

Postoje dva glavna tipa "trusted setup-a":

1. Setup po kolu (Per Circuit) - Groth16:

    - Šta je: Za svaki novi program (aritmetičko kolo) koji želiš da dokažeš, moraš da sprovedeš potpuno novu, specifičnu trusted setup ceremoniju. 

2. Univerzalni Setup (Universal) - PLONK:

    - Šta je: Sprovedeš jednu veliku trusted setup ceremoniju jednom, i njene rezultate možeš kasnije da iskoristiš za bilo koji program (do određene veličine).

NAPOMENA: G je generator grupe na eliptičkoj krivi sa kojom radimo.

## ZKP.16. Non-Interactive Preprocessing argument system (NIPAS).

Ovo je formalni naziv za vrstu ZKP sistema kao što je ZK-SNARK.

- Argument system: Kao što smo rekli, ovo je sistem gde Dokazivač (Prover) ubeđuje Verifikatora (Verifier) u istinitost neke izjave. 

- Preprocessing (Sa predobradom): Pre nego što bilo ko može da dokazuje ili verifikuje, mora da se izvrši Setup faza. 

    - Podsetnik: To je Trusted Setup ceremonija.

    - Ona stvara dva ključa: jedan za Dokazivača (Sp) i jedan za Verifikatora (Sv). 

- Non-Interactive (Neinteraktivan): Komunikacija je jednosmerna. Dokazivač pošalje jedan dokaz (π), i to je to. Nema ćaskanja napred-nazad kao u Ali Babinoj pećini.

### Tok celog procesa

1. Cilj: Dokazivač želi da dokaže da zna tajnog svedoka (witness) w koji zadovoljava neku jednačinu (npr. C(x,w) = 0), gde je x javni podatak. 

2. Faza Dokazivanja (Prover):

    - On uzima svoj ključ Sp, javni podatak x, i svoju tajnu w. 

    - Sve to ubacuje u algoritam za dokazivanje i dobija jedan kratak dokaz (proof), koji označavamo sa π. 

    - Šalje samo π Verifikatoru.

3. Faza Verifikacije (Verifier):

    - On uzima svoj ključ Sv, javni podatak x, i dokaz π koji je dobio. 

    - Sve to ubacuje u algoritam za verifikaciju.

    - Algoritam vraća samo "accept" (prihvati) ili "reject" (odbij).

## ZKP.17. KZG (Kate-Zaverucha-Goldberg).

KZG se oslanja na uparivanjima eliptičkih kriva.

Ceo proces ima tri koraka: Setup, Commit, i Eval.

1. Setup (Trusted Setup)

    - Proces:

        1. Izabere se tajni, nasumični broj s (to je "toksični otpad"). 

        2. Koristeći tajnu s i generator tačku G eliptičke krive, generišu se javni parametri: $[G,sG,s_2G,…,s_dG]$. 

        3. Tajna s se mora uništiti. 

2. Commit (Obavezivanje)

    - Cilj: Dokazivač ima svoj tajni polinom f(x) (koji predstavlja njegov svedok - witness) i želi da se obaveže na njega.

    - Proces: On uzima javne parametre iz Setup faze i izračunava komitment, koji je jedna tačka na eliptičkoj krivoj. Formula je 

        com(f) = [f(s)]G. 

    - Kako? Iako ne zna tajnu s, on može da izračuna komitment! Ako je njegov polinom npr. f(x) = 2x^2 + 3, on računa $2⋅(s^2G)+3⋅(G)$. Pošto su (s^2G) i (G) javni parametri, on lako dobija rezultat bez znanja o s.

3. Eval (Dokazivanje i Verifikacija)

    - Verifikatorov Izazov: Verifikator izabere javnu, nasumičnu tačku z i pita Dokazivača: "Koja je vrednost tvog tajnog polinoma f(x) u tački z?"

    - Dokazivačev Odgovor:

        1. Izračuna odgovor: y = f(z). 

        2. Izvede matematički trik: ako je f(z) = y, onda je polinom (f(x) - y) deljiv sa (x - z). (Teorema o ostatku polinoma)

        3. Izračuna novi, pomoćni polinom q(x) = (f(x) - y) / (x-z). 

        4. Napravi komitment na taj pomoćni polinom. Taj komitment, π = [q(s)]G, se zove dokaz o evaluaciji (evaluation proof). 

        5. Pošalje Verifikatoru odgovor y i dokaz π.

    - Verifikatorova Provera:

        - Verifikator sada treba da proveri da li je sve bilo pošteno, tj. da li važi f(s) - y = q(s) * (s-z). (Svarc-Zipel lema)

        - Pošto ne zna s, on ovo proverava "u eksponentu", koristeći uparivanja (pairings). 

        - Finalna provera je jedna jednačina sa uparivanjima koja proverava odnos između originalnog komitmenta com(f), odgovora y, pomoćnog dokaza π i javne tačke z. 

        - Ako se jednačina poklopi, Verifikator je ubeđen da je y zaista ispravna vrednost polinoma u tački z.

## ZKP.18. PLONK.

PLONK je moderan, efikasan i univerzalan ZK-SNARK sistem.

1. PLONK-ova Aritmetizacija

    - Inovacija: Stariji sistemi su imali veoma rigidna pravila za te jednačine. PLONK uvodi jednu, moćnu, univerzalnu formulu za "kapije" (gate constraints):

    $L_i⋅q_{L_i}​+R_i⋅q_{R_i}​+O_i⋅q_{O_i}​+q_{C_i}​+L_i​⋅R_i⋅q_{M_i}​​=0$

    Objašnjenje: Ne moraš da pamtiš formulu, već ideju. L, R i O su leva, desna i izlazna "žica" jedne operacije. q vrednosti su "selektori" koje Dokazivač (Prover) unapred podesi. Menjanjem ovih q selektora, ova jedna ista formula može da predstavlja i sabiranje, i množenje, i bilo koju drugu operaciju.

2. Argument Permutacije (za Copy Constraints)

    - Problem: Moramo dokazati da su "žice" između različitih operacija ispravno povezane (npr. da je izlaz iz operacije 1 zaista ulaz u operaciju 5).

    - PLONK-ovo rešenje: Umesto da se svaka veza proverava posebno, PLONK dokazuje da su sve žice koje treba da budu iste zaista iste pomoću jednog argumenta permutacije.

    - Šta je "Argument Permutacije"? To je kriptografski dokaz da su dva skupa vrednosti identična, samo što je jedan ispremeštan (permutovan) u odnosu na drugi.

    - Kako ga PLONK koristi?

        1. Stvaranje Dve Liste Vrednosti: PLONK uzme vrednosti svih žica u celom kolu (L₁, R₁, O₁, L₂, R₂, O₂...) i od njih napravi dve velike liste.

        2. Prva lista: Sadrži vrednosti žica grupisane po kapijama.

        3. Druga lista: Sadrži iste te vrednosti, ali ispremeštane (permutovane) tako da žice koje moraju biti jednake dođu na istu poziciju.

        4. Dokaz: PLONK zatim koristi pametan matematički trik sa polinomima da dokaže da su obe liste, iako različito poređane, u suštini identičan skup vrednosti. To se radi tako što se pokaže da je proizvod svih elemenata u prvoj listi jednak proizvodu svih elemenata u drugoj.

        5. Rezultat: Ako je dokaz uspešan, to znači da sve veze (copy constraints) u celom kolu važe. Ovo je mnogo efikasnije nego proveravati svaku vezu pojedinačno.

Kako sve radi zajedno:

1. Dokazivač prevede program u PLONK-ov sistem ograničenja.

2. Svoje tajne vrednosti (svedoka - witness) predstavi kao polinome.

3. Koristi KZG komitmente (17. pitanje) da se obaveže na te polinome.

4. Napravi argument permutacije da dokaže ispravnost veza.

5. Sve to spakuje u jedan PLONK dokaz.

6. Verifikator proverava sve ovo koristeći uparivanja (pairings).

## ZKP.19. Protokol Semafor (Semaphore).

Semaphore je ZK-SNARK protokol napravljen za anonimno signaliziranje, najčešće na Ethereum blockchainu.

- Cilj: Omogućiti korisniku da dokaže da je član neke grupe i da pošalje signal (npr. glas ili podršku), a da pritom ne otkrije svoj identitet unutar te grupe.

- Ključna funkcija: Pored anonimnosti, pruža i mehanizam za sprečavanje dvostrukog glasanja (double-signaling).

- Primene: Privatno glasanje, uzbunjivači (whistleblowing), anonimne decentralizovane organizacije (DAOs) i mikseri za kriptovalute.

Semaphore je kao slagalica sastavljena od delova koje smo već obradili:

1. Formiranje grupe pomoću Merkle Stabla

    - U Semaphore-u, "grupa" (npr. svi glasači) je predstavljena kao Merkle stablo. Svaki član kreira svoj identity commitment (vrsta kriptografskog identiteta) i ubacuje ga kao list (leaf) u stablo. Merkle root tog stabla je javan i služi kao identifikator grupe.

2. Slanje signala pomoću ZK-SNARK dokaza

    - Kada korisnik želi da pošalje signal (npr. da glasa), on ne šalje samo svoj glas. On kreira ZK-SNARK dokaz koji istovremeno potvrđuje dve stvari:

        - Dokaz o članstvu (Proof of Membership): Korisnik dokazuje da se njegov tajni "identity commitment" zaista nalazi u Merkle stablu koje odgovara javnom Merkle root-u.

            - Podsetnik: Ovo se radi pomoću Merkle putanje, kao što smo detaljno objasnili. Dokaz potvrđuje pripadnost bez otkrivanja identiteta.

        - Sprečavanje duplog glasanja (Nullifiers): Korisnik takođe dokazuje da za dati signal (npr. za "izbore 2025.") koristi jedinstveni nullifier.

            - Šta je Nullifier? To je jedinstveni broj koji se dobija iz korisnikove tajne i konteksta signala (npr. ID izbora).

            - Kada se dokaz pošalje, taj nullifier se javno objavljuje na listi "iskorišćenih".

            - Pre prihvatanja novog dokaza, sistem proverava da li se njegov nullifier već nalazi na listi.

            - Pošto je nullifier kriptografski nepovezan sa identitetom korisnika, privatnost je sačuvana, a dvostruko glasanje je onemogućeno.

Protokol Semafor je sjajan primer kako se apstraktni koncepti — Aritmetizacija, Merkle stabla, Polinomski komitmenti i ZK-SNARKovi — spajaju da bi rešili stvarne probleme, kao što je potreba za privatnim i sigurnim glasanjem u digitalnom svetu.

## ZKP.Rezime

- Osnove ZKP-a: Zero-Knowledge Proof (ZKP) je metod gde Dokazivač ubeđuje Verifikatora da je izjava tačna, bez otkrivanja bilo kakvih dodatnih informacija osim istinitosti same izjave. Svaki ZKP mora da zadovolji tri svojstva: 

    Potpunost (ako je istina, dokaz prolazi), Ispravnost (ako je laž, dokaz pada) i Nulto znanje (verifikator ne saznaje tajnu).

- Matematička osnova: Sigurnost mnogih sistema se oslanja na teške probleme kao što je Problem diskretnog logaritma (DLP) , a posebno na njegovu efikasniju varijantu na eliptičkim krivama (ECDLP). 

    Uparivanja (Pairings) su ključna operacija koja omogućava proveru jednačina sa množenjem u ZK-SNARK sistemima.

- SNARK vs. STARK: Ovo su dve glavne vrste ZKP sistema.

    - SNARK (Succinct Non-Interactive Argument of Knowledge) nudi veoma male dokaze i brzu verifikaciju , ali često zahteva trusted setup.

    - STARK (Scalable Transparent Argument of Knowledge) ne zahteva trusted setup (transparentan je) i otporan je nа kvantne kompjutere, ali ima veće dokaze.

- Izgradnja SNARK-a: Proces počinje Aritmetizacijom, gde se program pretvara u sistem jednačina (ograničenja). Tajni podaci (svedok) se predstavljaju kao polinomi, a na njih se Dokazivač obavezuje pomoću Polinomskih komitmenata kao što je KZG.

- PLONK & Semaphore: PLONK je moderan ZK-SNARK sa univerzalnim trusted setup-om i efikasnim argumentom permutacije za proveru veza u kolu. 

    Semaphore je praktičan protokol koji koristi Merkle stabla za dokazivanje članstva u grupi i nullifiere za sprečavanje dvostrukog glasanja.

## ZKP.Zadaci

### 1. Нека је дато коначно поље Fp​, где је p=113. Нека су дати полиноми p(x)=2x^4−4x^3+4x^2−4x+2 и q(x)=x^3−x^2+x−1. Израчунати вероватноћу да се случајним избором броја из коначног поља Fp​ погоди заједничка нула полинома р и q.

Ovo je problem koji se oslanja na Schwartz-Zippel lemu. Lema kaže da je verovatnoća da nasumični element bude koren nekog polinoma veoma mala. 

Da bismo rešili zadatak, potrebna su nam dva podatka:

1. Koliko elemenata ima u polju F113​?
    
    - Imamo 113 elemenata.

2. Koliko zajedničkih nula (korena) imaju polinomi p(x) i q(x)?

    - q(x) ima 3 nule koje se poklapaju sa nulama p(x), tako da ova dva polinoma imaju zajedničke nule.

Verovatnoća je zato 3/113.

### 2. Написати Circom код за коло којим се проверава да ли особа за дату јавну вредност Посејдон хеша зна број чијим се хеширањем добија та вредност.

```circom
pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

template PoseidonVerifier() {
    // 1. Ulazi (Inputs)
    signal input secret;      // Privatni ulaz: tajni broj koji samo Dokazivač zna
    signal input publicHash; // Javni ulaz: heš koji je svima poznat

    // 2. Komponenta
    // Pozivamo Poseidon hešer iz biblioteke. Očekuje 1 ulaz i daje 1 izlaz.
    component hasher = Poseidon(1);

    // 3. Povezivanje "žica"
    // Kažemo da ulaz u hešer treba da bude naš tajni broj.
    hasher.inputs[0] <== secret;

    // 4. Ograničenje (Constraint)
    // Ovo je srž kola. Namećemo ograničenje da izlaz iz hešera
    // MORA BITI JEDNAK javnom hešu.
    hasher.out === publicHash;
}

// Glavna komponenta koja pokreće naše kolo.
// Deklarišemo da je 'publicHash' javni ulaz za ceo ZK-SNARK.
component main {public [publicHash]} = PoseidonVerifier();

```

### 3. Potapanje brodova

```circom

/*

Potapanje brodova (eng. Battleship) je igra koju igraju dva igrača.

Svaki igrač rasporedjuje svoje brodove na kvadratnu tablu


Više o igri možete pročitati ovde: https://en.wikipedia.org/wiki/Battleship_(game)

*/


pragma circom 2.1.6;


include "circomlib/poseidon.circom";

include "circomlib/comparators.circom";

include "circomlib/mux1.circom";


template Tabla(N) {

signal input tabla [N][N];

signal input ii;

signal input jj;

signal output odgovor;

/* prvi pokušaj: jednostavno proveravamo da li se podmornica nalazi

na polju sa koordinatama ii i jj. Ako se nalazi vraćamo 1, u suprotnom vraćamo 0:


component pogodak = IsEqual();

pogodak.in[0] <== tabla[ii][jj];

pogodak.in[1] <== 1;

odgovor <== pogodak.out;


Ovaj kod neće raditi jer ii i jj nisu poznati u trenutku kompilacije,

pa ne smemo da ih koristimo za pristupanje matrici tabla[N][N],

jer mogu da budu van opsega


drugi pokušaj:

signal pogodak;

component polje = Mux1();

for(var i=0; i<N; i++)

{

    for(var j=0; j<N; j++)

    {

        if(i==ii)

        {

            if(j==jj)

            {

               polje.c[0]<==0;

               polje.c[1]<==1;

               polje.s <== tabla[i][j];

               pogodak <== polje.out; 

            }

        }

    }

}

odgovor <== pogodak;       


Ni ovaj kod neće raditi. Neophodno je da aritmetizujemo if-ove.

To radimo koristeći multipleksere. Za multiplekser imamo gotov template

Mux1 u circomlib/mux1.circom

*/


// treći (konačno ispravan) pokušaj:

/* U svakoj iteraciji dvostruke for petlje ćemo proveravati da li smo

naišli na polje koje je gadjao protivnik. Dakle, moramo da izvršimo NxN

provera za obe koordinate. Pošto se deklaracija component-i ne može

vršiti u for petlji, moramo sve componente da deklarišemo pre for petlje  */

component jednakii[N][N];

component jednakij[N][N];

component polje[N][N];

var pogodak = 0;

/* ako hoćemo da budemo maksimalno formalni i da svuda budemo

pokriveni constraint-ovima onda bi umesto var trebalo da koristimo

NxN matricu signala */

for(var i=0; i<N; i++)

{

    for(var j=0; j<N; j++)

    {

        jednakii[i][j]=IsEqual();

        jednakii[i][j].in[0] <==ii;

        jednakii[i][j].in[1] <==i;


        jednakij[i][j]=IsEqual();

        jednakij[i][j].in[0] <==jj;

        jednakij[i][j].in[1] <==j;


        polje[i][j]=Mux1();

        polje[i][j].c[0] <== 0;

        polje[i][j].c[1] <== tabla[i][j];

        polje[i][j].s <== jednakii[i][j].out * jednakij[i][j].out;

/* ako smo naišli na polje koje je gadjao protivnik (tj. ako je selektorski

bit jednak 1), onda je izlaz iz multipleksera vrednost koja se nalazi na tom polju

(tj. vrednost tabla[i][j]), a za sva ostala polja izlaz je 0 */

        pogodak += polje[i][j].out;

/* sabiramo sve izlaze, tj. sabiramo 24 nule i vrednost na polju

koje je gadjao protivnik (dakle, pogodak če imati vrednost 0 ili 1) */

    }

}

odgovor <== pogodak;

}


component main {public [ii, jj]} = Tabla(5);


//primer inputa:


/* INPUT = {

"tabla": [["0","1","1","0","1"],["0","0","0","0","1"],

["1","1","1","0","1"],["0","0","0","0","1"],["0","0","1","1","0"]],

"ii": "1",

"jj": "2"

} */


/*

Ovo je tabla koju šaljemo kao input

0 1 1 0 1

0 0 0 0 1

1 1 1 0 1

0 0 0 0 1

0 0 1 1 0

*/

``` 

# Blockhain

## BC.1. Особине блокчејна.

U suštini, blokčejn je kao digitalna knjiga (ledger) koja je istovremeno podeljena na hiljade računara. Svaka nova informacija (transakcija) se dodaje kao novi "blok" na "lanac" postojećih informacija.  Ono što ga čini posebnim su njegove jedinstvene osobine.

### 1. Decentralizacija

U tradicionalnim sistemima, poput banke, sve podatke kontroliše jedna centralna institucija. Blokčejn je drugačiji – on je decentralizovan. To znači da ne postoji jedan centralni autoritet ili server koji sve kontroliše. Umesto toga, kopija cele knjige transakcija je distribuirana među svim učesnicima u mreži (zvanim "čvorovi").

### 2. Nepromenljivost (Immutability)

Jednom kada se transakcija zabeleži u blok i taj blok se doda u lanac, podaci u njemu se ne mogu menjati niti brisati. Svaki blok je kriptografski povezan sa prethodnim blokom pomoću heša (jedinstvenog digitalnog otiska).  Ako bi neko pokušao da promeni podatke u jednom bloku, heš tog bloka bi se promenio. Pošto je taj heš deo sledećeg bloka, promenio bi se i heš sledećeg bloka, i tako redom kroz ceo lanac. Takva promena bi odmah bila primećena i odbačena od strane ostatka mreže.

### 3. Transparentnost

Iako se identitet učesnika može sakriti iza pseudonima (adresa novčanika), sve transakcije koje se dese na javnom blokčejnu su vidljive svima u mreži. Svako može da pogleda celu istoriju transakcija od samog početka (od prvog, "genesis" bloka). Ovo stvara nivo poverenja jer nema skrivenih radnji.

### 4. Sigurnost

Sigurnost blokčejna proizlazi iz kombinacije decentralizacije, nepromenljivosti i kriptografije. Svaka transakcija je digitalno potpisana pomoću privatnog ključa vlasnika, što dokazuje autentičnost. Struktura lanca, gde je svaki blok osiguran hešom prethodnog, čini ga izuzetno otpornim na neovlašćene promene. Da bi haker uspešno napao mrežu, morao bi da kontroliše više od 51% računarske snage cele mreže, što je praktično nemoguće na velikim mrežama poput Bitcoina.

### 5. Sistem bez potrebe za poverenjem (Trustless)

Paradoksalno, blokčejn se naziva "trustless" sistemom. To ne znači da mu se ne može verovati, već da ne morate verovati nijednom pojedinačnom učesniku u mreži. Poverenje je ugrađeno u sam sistem – u matematiku, kriptografiju i konsenzus mehanizam (pravila po kojima se svi slažu). Možete obaviti transakciju sa potpunim strancem bez posrednika (kao što je banka) jer znate da će se pravila protokola ispoštovati.

## BC.2. Предности и мане блокчејн технологије.

### Prednosti

- Integritet i sigurnost podataka: Jednom uneti podaci su praktično nepromenljivi, a ceo sistem je osiguran kriptografijom, što ga čini otpornim na prevare i hakerske napade.

- Decentralizacija: Ne postoji centralna tačka kvara ili kontrole, što sistem čini otpornim na cenzuru ili padove servera.

- Transparentnost i sledljivost (Traceability): Sve transakcije se mogu pratiti unazad do samog početka, što je idealno za, na primer, praćenje lanca snabdevanja (da znaš tačno odakle potiče kafa koju piješ).

- Brže transakcije: Posebno kod međunarodnih plaćanja, blokčejn može smanjiti vreme transakcije sa nekoliko dana na minute, jer eliminiše posrednike.

- Automatizacija: Kroz "pametne ugovore" (smart contracts), procesi se mogu automatizovati, smanjujući potrebu za manuelnim radom i papirologijom.

### Mane

- Potrošnja energije: Posebno kod "Proof of Work" sistema kao što je Bitcoin, proces "rudarenja" (verifikacije transakcija) zahteva ogromnu količinu električne energije, što je veliki ekološki problem.

- Skalabilnost: Mreže poput Bitcoina i Ethereuma mogu da obrade relativno mali broj transakcija u sekundi (Bitcoin 3-7, Ethereum 10-20). U poređenju sa VISA sistemom koji obrađuje hiljade, ovo je veliko ograničenje.

- Veličina skladišta (Storage): Pošto svaki "full node" mora da čuva kopiju celog lanca, baza podataka vremenom postaje ogromna. Bitcoin-ov blokčejn trenutno zauzima stotine gigabajta.

- Složenost i nezrelost: Tehnologija je i dalje nova i kompleksna za razumevanje i implementaciju. Nedostaje standardizacija i kvalifikovanih programera.

- Ranjivost na "51% napad": Iako teško izvodljivo, ako jedna osoba ili grupa preuzme kontrolu nad više od polovine računarske snage mreže, teoretski može da manipuliše transakcijama.

- Problem izmene podataka: Nepromenljivost je mač sa dve oštrice. Ako postoji greška u pametnom ugovoru ili je potrebno izmeniti podatke iz legitimnog razloga (npr. GDPR "pravo na zaborav"), to je skoro nemoguće izvesti bez komplikovanih procedura koje dele mrežu (tzv. "fork").

## BC.3. Примене блокчејн технологије.

### 1. Bankarstvo i finansije 

- Međunarodna plaćanja: Ubrzava prenos novca preko granica i smanjuje troškove eliminisanjem posredničkih banaka.  Kao kad bi Lelouch naredio direktan transfer novca bez čekanja na birokratiju.

- Tržišta kapitala: Ubrzava procese kliringa i poravnanja transakcija sa akcijama i drugim hartijama od vrednosti. 

- Zaštita od pranja novca: Transparentnost blokčejna pomaže u praćenju sumnjivih transakcija i olakšava "Know Your Customer" (KYC) procedure. 

- Osiguranje: Pametni ugovori mogu automatski da obrade zahteve za odštetu čim se ispune unapred definisani uslovi (npr. automatska isplata za otkazan let). 

### 2. Poslovanje i industrija

- Upravljanje lancem snabdevanja (Supply Chain Management): Ovo je jedna od najvećih primena. Omogućava praćenje proizvoda od fabrike do police u realnom vremenu. Svaki učesnik u lancu (proizvođač, prevoznik, carina, prodavac) može da zabeleži svoj korak na nepromenljivom blokčejnu, garantujući autentičnost i poreklo proizvoda.  To je kao da Lelouch naredi svakoj osobi u lancu da "istinito i javno zabeleži kada si primio i predao paket".

- Zdravstvo: Pacijenti mogu imati kontrolu nad svojim zdravstvenim kartonima, koji su sigurno sačuvani na blokčejnu i mogu ih deliti sa doktorima po potrebi, bez rizika da podaci budu kompromitovani. 

- Nekretnine: Ubrzava i pojednostavljuje proces kupoprodaje nekretnina, smanjuje papirologiju i mogućnost prevare proverom vlasništva. 

- Mediji i zabava: Umetnici mogu da zaštite svoja autorska prava (IP) i automatski prate i naplaćuju korišćenje svoje muzike ili videa putem pametnih ugovora. 

### 3. Vlada i javni sektor 

- Upravljanje javnim podacima: Vlade mogu da koriste blokčejn za sigurno čuvanje podataka građana kao što su izvodi iz matične knjige rođenih, podaci o imovini i venčani listovi, čineći ih otpornim na falsifikovanje.  Kao da je svaki dokument u Britaniji zaštićen Geass-om koji sprečava njegovu izmenu.

- Glasanje (Voting): Blokčejn može omogućiti sigurno i transparentno glasanje, gde je svaki glas zabeležen i ne može se promeniti, a istovremeno se čuva anonimnost glasača. Time se smanjuje rizik od izborne krađe. 

- Porezi: Može da pojednostavi i automatizuje proces prikupljanja poreza, čineći ga efikasnijim i transparentnijim. 

- Nevladine organizacije (NGO): Donatori mogu da prate kako se njihov novac troši, jer svaka transakcija unutar organizacije može biti javno zabeležena na blokčejnu. 

### 4. Ostale industrije

- Sajber bezbednost: Eliminiše centralnu tačku napada, što povećava otpornost sistema na hakere. 

- Internet Stvari (IoT): IoT uređaji mogu sigurno da komuniciraju i razmenjuju podatke preko blokčejn mreže. 

- Poljoprivreda: Koristi se za praćenje porekla poljoprivrednih proizvoda i osiguravanje kvaliteta hrane.

## BC.4. Изазови за усвајање блокчејн технологије.

### 1. Skalabilnost i brzina transakcija

Ovo je jedan od najvećih tehničkih problema. Mreže kao što su Bitcoin i Ethereum mogu da obrade samo mali broj transakcija u sekundi (TPS). U poređenju sa sistemima kao što je VISA koji obrađuju hiljade, ovo je nedovoljno za globalnu primenu u plaćanju ili drugim industrijama koje zahtevaju veliku brzinu.

### 2. Visoka potrošnja energije

Mehanizam konsenzusa "Proof of Work" (PoW), koji koriste Bitcoin i (do nedavno) Ethereum, zahteva ogromnu računarsku snagu i, posledično, ogromnu količinu električne energije. Ovo ne samo da je skupo, već je i ekološki neodrživo, što odbija mnoge kompanije i investitore.

### 3. Regulativa i pravna nesigurnost

Vlade širom sveta još uvek pokušavaju da shvate kako da regulišu blokčejn i kriptovalute. Nedostatak jasnih zakona stvara nesigurnost za preduzeća koja žele da usvoje tehnologiju. Pored toga, karakteristike blokčejna, poput nepromenljivosti podataka, dolaze u sukob sa zakonima kao što je GDPR u Evropskoj Uniji, koji garantuje "pravo na zaborav".

### 4. Interoperabilnost

Većina blokčejn mreža su zatvoreni ekosistemi koji ne mogu lako da komuniciraju jedni sa drugima. Ne možete jednostavno poslati Bitcoin na Ethereum adresu. Ovaj nedostatak interoperabilnosti je kao da imate internet, ali korisnici jedne mreže ne mogu da šalju imejlove korisnicima druge. Velike kompanije poput IBM-a i Oracle-a rade na rešenjima, ali problem i dalje postoji.

### 5. Sigurnosni rizici

Iako je sama tehnologija sigurna, primene izgrađene na njoj, kao i korisnici, mogu biti ranjivi. Napadi poput "51% napada" teoretski su mogući. Takođe, hakovani su mnogi centralizovani servisi (menjačnice), što je dovelo do gubitka stotina miliona dolara i narušilo poverenje u ekosistem.

### 6. Troškovi i složenost

Razvoj i implementacija blokčejn rešenja su skupi i tehnički zahtevni. Postoji globalni nedostatak iskusnih blokčejn programera, što dodatno povećava troškove.

## BC.5. Основни елементи блокчејна.

### 1. Decentralizovana mreža (Decentralized Network)

Ovo je "igraonica" ili pozornica. Blokčejn ne postoji na jednom računaru, već se oslanja na mrežu hiljada računara (čvorova) koji međusobno komuniciraju direktno, bez posrednika (peer-to-peer ili P2P). Svaki čvor u mreži doprinosi svojim resursima za čuvanje podataka i obradu transakcija.

### 2. Matematička kriptografija (Mathematical Cryptography)

Ovo su "pravila igre". Kriptografija pruža matematičke dokaze koji garantuju da sistem funkcioniše kako treba. Dve ključne primene su:

- Heš funkcije: Povezuju blokove u lanac i osiguravaju da se podaci ne mogu menjati.

- Kriptografija sa javnim ključem: Omogućava digitalne potpise, potvrđujući da je transakciju poslao stvarni vlasnik naloga i da je namenjena pravom primaocu.

### 3. Distribuirani konsenzus (Distributed Consensus)

Ovo je "proces odlučivanja". Pošto nema centralnog autoriteta, čvorovi u mreži moraju imati mehanizam da se slože oko toga koja verzija istorije je tačna. Ovo se postiže kroz algoritme konsenzusa, kao što su Proof-of-Work (dokaz o radu) ili Proof-of-Stake (dokaz o ulogu).

### 4. Knjiga transakcija (Transaction Ledger)

Ovo je "zapis događaja". Blokčejn je u suštini digitalna knjiga (ledger) u koju se transakcije hronološki upisuju u blokove. Novi blokovi se uvek dodaju na kraj lanca, kao nove stranice u knjizi koja se samo dopunjuje (append-only).

### 5. Pametni ugovori (Smart Contracts)

Ovo su "automatizovana pravila sa posledicama". Pametni ugovor je jednostavno kompjuterski program koji se čuva i izvršava na blokčejnu. On automatski sprovodi uslove nekog dogovora kada se ispune unapred definisani uslovi, bez potrebe za posrednikom.

## BC.6. Криптографски елементи блокчејн технологије.

Kriptografija je nauka o sigurnoj komunikaciji. U blokčejnu, ona nije tu samo da sakrije podatke, već da pruži matematički dokaz o integritetu, autentičnosti i sigurnosti celog sistema. Dva glavna stuba kriptografije u blokčejnu su heš funkcije i kriptografija sa javnim ključem.

### 1. Kriptografske heš funkcije

Heš funkcija je kao magična mašina za mlevenje. U nju možete ubaciti bilo šta – tekst, sliku, ceo fajl (ulaz) – a ona će uvek izbaciti jedinstveni niz slova i brojeva fiksne dužine (izlaz), koji se zove heš ili "digitalni otisak". 

Da bi bila kriptografska, heš funkcija mora imati tri ključne osobine: 

- Otpornost na koliziju (Collision-resistant): Praktično je nemoguće pronaći dva različita ulaza koja bi proizvela isti heš izlaz. Svaki, pa i najmanji, delić promene na ulazu stvara potpuno drugačiji heš.

- Sakrivanje (Hiding): Ako imate samo heš (izlaz), praktično je nemoguće otkriti koji je bio originalni ulaz. To je jednosmerna ulica.

- Pogodnost za zagonetke (Puzzle-friendly): Ako znate heš i deo ulaza, jedini način da pronađete ostatak ulaza je nasumično pogađanje (brute-force). Ovo je ključno za rudarenje.

Primene u blokčejnu:

1. Povezivanje blokova: Svaki blok u lancu sadrži heš prethodnog bloka.  Ovo stvara neraskidivu vezu. Ako bi neko promenio podatke u jednom bloku, njegov heš bi se promenio, što bi prekinulo vezu sa sledećim blokom i ceo lanac bi postao nevažeći. Ovo osigurava nepromenljivost.

2. Sažimanje podataka: Merkle drvo (o kojem ćemo kasnije) koristi heševe da efikasno sažme sve transakcije u jednom bloku u jedan jedini heš (Merkle root) koji se čuva u zaglavlju bloka. 

### 2. Kriptografija sa javnim ključem (Asimetrična kriptografija)

Ovaj sistem koristi par matematički povezanih ključeva za svakog korisnika:

- Privatni ključ (Private Key): Ovo je tvoja tajna. Čuvaš ga samo za sebe i nikome ga ne otkrivaš. Koristi se za "potpisivanje" transakcija. 

- Javni ključ (Public Key): Ovo je ključ koji slobodno deliš sa svima. Iz njega se izvodi tvoja adresa na blokčejnu, na koju ti drugi šalju sredstva. 

Glavna primena ovde je digitalni potpis. 

1. Kada želiš da pošalješ transakciju, ti je "potpisuješ" svojim privatnim ključem.

2. Mreža zatim koristi tvoj javni ključ da proveri da li je potpis validan.

Ovo dokazuje dve stvari:

- Autentičnost: Da si zaista ti, vlasnik privatnog ključa, odobrio transakciju.

- Integritet: Da transakcija nije promenjena nakon što si je potpisao.

## BC.7. Проблем дистрибуираног консензуса.

Ukratko, problem distribuiranog konsenzusa je pitanje: 

**Kako grupa nezavisnih pojedinaca, koji ne veruju u potpunosti jedni drugima, može da se dogovori oko jedne istine?**

U centralizovanom sistemu, ovo je lako. Banka kaže: "Stanje na tvom računu je X", i to je istina. Ali u decentralizovanoj mreži kao što je blokčejn, nema "šefa" koji odlučuje. Svi čvorovi (učesnici) su jednaki. Šta se dešava ako različiti čvorovi vide različite stvari? Šta ako neki čvorovi namerno lažu?

Da bi se ovo slikovito objasnilo, informatičari su smislili priču poznatu kao **Problem vizantijskih generala (The Byzantine Generals' Problem)**.

Priča ide ovako:

Grupa vizantijskih generala opkolila je neprijateljski grad. Moraju da donesu zajedničku odluku: NAPAD ili POVLAČENJE. Ako svi napadnu zajedno, pobediće. Ako se svi povuku, preživeće. Ali, ako neki napadnu, a neki se povuku, pretrpeće katastrofalan poraz.

Problem je što generali mogu da komuniciraju samo putem glasnika, a među njima ima izdajnika. Izdajnik može da pokuša da sabotira plan. Na primer, izdajnički general može jednom lojalnom generalu reći "Napadamo!", a drugom "Povlačimo se!", kako bi izazvao haos i osigurao poraz.

Pitanje je: Da li postoji algoritam (strategija) koji lojalni generali mogu da prate kako bi se svi složili oko istog plana, bez obzira na to šta izdajnici rade?

Ovo je isti problem sa kojim se suočava blokčejn:

- Generali = Čvorovi u mreži.

- Plan (Napad/Povlačenje) = Sledeći validan blok transakcija.

- Izdajnici = Zlonamerni čvorovi koji pokušavaju da prevare sistem (npr. da potroše isti novac dva puta - "double spending").

- Glasnici = Internet konekcija kojom čvorovi komuniciraju.

Sistem koji može da reši ovaj problem i postigne dogovor uprkos prisustvu "izdajnika" naziva se **Vizantijski tolerantno na greške (Byzantine Fault Tolerant - BFT)**.

Dakle, algoritmi konsenzusa (kao što su Proof-of-Work i Proof-of-Stake) su upravo ta rešenja. Oni su skupovi pravila koji omogućavaju decentralizovanoj mreži da postigne dogovor i ostane sigurna, čak i kada su neki njeni delovi nepouzdani ili zlonamerni.

## BC.8. Консензус заснован на доказу рада (Proof of Work - PoW)

Proof of Work (PoW), ili Dokaz o radu, je bio prvi i najpoznatiji algoritam konsenzusa, proslavljen od strane Bitcoina. To je mehanizam koji osigurava da dodavanje novih blokova u lanac bude teško, skupo i zahteva vreme, ali da provera tog novog bloka bude laka za sve ostale.

Osnovna ideja je da učesnici, zvani rudari (miners), moraju da ulože stvarni resurs – računarsku snagu (rad) – da bi dobili pravo da dodaju novi blok.

Kako funkcioniše?

1. Sakupljanje transakcija: Rudari slušaju mrežu i prikupljaju nove, nepotvrđene transakcije. Formiraju ih u kandidat-blok.

2. Rešavanje zagonetke: Da bi njihov blok bio prihvaćen, rudar mora da reši složenu kriptografsku zagonetku. Zagonetka se svodi na sledeće: pronađi nasumični broj, koji se zove "nonce".

3. Uslov zagonetke: Kada se taj "nonce" spoji sa podacima iz bloka i sve se provuče kroz heš funkciju (kod Bitcoina, to je SHA-256 dva puta), rezultujući heš mora biti manji od određene ciljne vrednosti (target). Drugim rečima, heš mora da počinje sa određenim brojem nula.

4. Brutalna sila (Brute Force): Pošto su heš funkcije nepredvidive, jedini način da se pronađe pravi "nonce" je nasumičnim pogađanjem. Rudari koriste specijalizovan hardver da isprobaju milijarde i milijarde "nonce"-ova svake sekunde. To je kao da pokušavate da pronađete jednu specifičnu kap vode u okeanu.

5. Pobeda i nagrada: Prvi rudar koji pronađe "nonce" koji daje željeni heš "pobeđuje" u rundi. On objavljuje svoj blok i rešenje (nonce) celoj mreži.

6. Laka provera: Ostali čvorovi u mreži uzmu taj blok, dodaju mu pobednički "nonce", provuku ga kroz heš funkciju i odmah vide da li je rešenje tačno. Ako jeste, prihvataju blok i dodaju ga u svoju kopiju lanca.

7. Nagrada: Pobednički rudar dobija nagradu u vidu novostvorenih novčića (npr. Bitcoina) i svih provizija od transakcija koje je uključio u svoj blok.

Zašto ovo rešava problem konsenzusa?

PoW rešava problem Vizantijskih generala tako što pravo glasa vezuje za nešto što se ne može lako lažirati: rad. Izdajnički general ne može samo da viče "Napadamo!" hiljadu puta. U PoW svetu, on mora da uloži ogroman rad (energiju i računarsku snagu) za svaki "glas" (svaki blok).

Da bi zlonamerni akter uspeo da promeni istoriju (npr. da vrati transakciju koju je već poslao), morao bi da ponovo "izrudi" taj blok i sve blokove koji su došli posle njega, i to brže od cele ostatka mreže zajedno. To bi zahtevalo kontrolu nad više od 51% ukupne računarske snage mreže, što je neverovatno skupo i praktično nemoguće na velikim mrežama. Cena napada je veća od potencijalne koristi.

Problem: Ogromna potrošnja energije.

### Digresija o targetu, ulazu i izlazu heš funkcije

Šta je target?

Zamislite da rudari bacaju kockice i pokušavaju da dobiju broj manji od, na primer, 10. "10" je u tom slučaju target. U svetu Bitcoina, "target" je jedan ogroman broj. Heš koji rudar izračuna mora biti manji od tog broja da bi bio validan. Što je target manji, to je teže "ubosti" heš koji je manji od njega, i time je zagonetka teža.

Ko ga određuje?

Ne određuje ga nijedna osoba ili kompanija. Određuje ga sam Bitcoin protokol – softver koji svi učesnici koriste. To je jedno od osnovnih pravila ugrađenih u sistem.

Kako se određuje?

Ovo je genijalan deo. Protokol automatski podešava težinu (difficulty), a time i target, svake 2016. bloka (što je otprilike svake dve nedelje). Cilj je da se, u proseku, jedan novi blok pronađe na svakih 10 minuta.

-  Ako su rudari u prethodne dve nedelje pronalazili blokove brže od 10 minuta (npr. na svakih 8 minuta jer se mnogo novih rudara priključilo), protokol će povećati težinu (smanjiće target broj) za sledeći period.

- Ako su pronalazili blokove sporije (npr. na svakih 12 minuta), protokol će smanjiti težinu (povećaće target broj) da bi olakšao posao.

Ovaj mehanizam osigurava stabilan i predvidiv "otkucaj srca" mreže, bez obzira na to koliko je rudara aktivno.

Ulaz u heš funkciju NIJE ceo blok, već ZAGLAVLJE BLOKA (Block Header).
Zaglavlje bloka je mali deo bloka koji sadrži ključne informacije: heš prethodnog bloka, sažetak svih transakcija (Merkle root), vreme, i ono što je najvažnije za ovu priču - nonce.

Izlaz iz heš funkcije NIJE nonce, već HEŠ VREDNOST (Hash Value).

Dakle, proces izgleda ovako:

1. Rudar uzme zaglavlje bloka.

2. U to zaglavlje stavi neki nasumični broj za nonce.

3. ULAZ = Zaglavlje bloka (sa sve nonce-om)

4. Rudar propusti taj ulaz kroz heš funkciju (npr. SHA-256).

5. IZLAZ = Heš vrednost (npr. 00000000000000000005d7a...)

6. Rudar pogleda izlaz (heš). Da li je manji od targeta?

    - Ako jeste, super! Rudar je rešio zagonetku.

    - Ako nije, rudar menja nonce (stavi drugi broj) i ponavlja ceo proces. I tako milijarde puta u sekundi.

Nonce je, dakle, mali deo ULAZA koji rudar neprestano menja da bi dobio željeni IZLAZ (heš ispod targeta).

## BC.9. Консензус заснован на доказу улагања.

Proof of Stake (PoS) je klasa algoritama konsenzusa gde se pravo na kreiranje novog bloka ne stiče rešavanjem kriptografske zagonetke, već na osnovu količine novčića (kriptovalute) koju je učesnik spreman da "uloži" ili "zaključa" kao zalog. 

Umesto rudara (miners), ovde imamo validatore. Umesto takmičenja u računarskoj snazi, imamo neku vrstu lutrije u kojoj verovatnoća da budete izabrani da kreirate sledeći blok zavisi od veličine vašeg uloga.

Kako funkcioniše?

1. Ulaganje (Staking): Korisnici koji žele da učestvuju u procesu validacije moraju da zaključaju određenu količinu svojih novčića kao zalog.  Time postaju validatori.

2. Proces selekcije: Protokol zatim na pseudo-slučajan način bira jednog validatora da kreira sledeći blok. Što veći ulog imate, veće su šanse da budete izabrani.  Zamislite da je svaki novčić koji ste uložili jedan tiket za lutriju.

3. Kreiranje i potvrda bloka: Izabrani validator kreira novi blok sa transakcijama, potpisuje ga i predlaže mreži. Ostali validatori zatim glasaju i potvrđuju (attest) da je blok validan.

4. Nagrada: Kada je blok potvrđen i dodat u lanac, validator koji ga je kreirao dobija nagradu u vidu provizija od transakcija u tom bloku.

Zašto ovo rešava problem konsenzusa?

PoS menja fundamentalni princip osiguranja mreže. Umesto da vas tera da trošite spoljni resurs (struju), PoS vas tera da kao zalog stavite interni resurs – samu kriptovalutu.

Sigurnost potiče iz ekonomskog podsticaja. Validator koji bi pokušao da prevari sistem (npr. da potvrdi lažnu transakciju) bio bi kažnjen oduzimanjem dela ili čak celog svog uloga. Ovaj proces se zove "slashing". 

Pošto validator ima "kožu u igri" (skin in the game), u njegovom je najboljem interesu da se ponaša pošteno i održava mrežu sigurnom, jer bi u suprotnom izgubio svoj novac.  Potencijalni gubitak je daleko veći od potencijalnog dobitka od prevare.

- Glavna prednost: Drastično smanjuje potrošnju energije u poređenju sa PoW. 

- Potencijalna mana: Rizik od centralizacije, gde najbogatiji učesnici imaju najveću moć u mreži. Zbog toga postoje varijacije kao što su Delegated PoS (DPoS) i Leased PoS (LPoS) koje pokušavaju da reše ovaj problem.

Ukratko:

- PoW: Sigurnost kroz rad i potrošnju energije.

- PoS: Sigurnost kroz ekonomski zalog i strah od gubitka.

### Digresija

#### 1. Kako ostali validatori glasaju i potvrđuju da je blok validan?

U PoS sistemima kao što je novi Ethereum, proces je elegantan i organizovan. Zamisli da su svi aktivni validatori podeljeni u "komitete" za svaki mali vremenski period (slot, npr. 12 sekundi).

1. Predlagač i potpisnici: U svakom slotu, jedan validator je nasumično izabran da bude predlagač bloka (block proposer). Ostali validatori u komitetu su potpisnici (attesters).

2. Predlaganje bloka: Predlagač sakupi transakcije, formira blok, potpiše ga svojim privatnim ključem i pošalje ga mreži.

3. "Glasanje" kroz potpisivanje (Attestation): Ostali validatori (potpisnici) primaju taj blok. Njihov zadatak je da ga provere. Ako provere da je blok ispravan (o tome šta to znači, u sledećem pitanju), oni kreiraju poruku koja kaže otprilike: "Da, video sam ovaj blok, proverio sam ga i slažem se da je validan." Ovu poruku potpisuju svojim privatnim ključem i šalju je mreži. Ta potpisana poruka je atestacija (attestation), što je zapravo njihov "glas".

4. Finalizacija: Blok se ne smatra odmah "uklesanim u kamen". On postaje sve "jači" kako se atestacije (glasovi) drugih validatora prikupljaju i zapisuju u naredne blokove. Kada dovoljan broj validatora (obično dvotrećinska većina) glasa za taj blok tokom određenog perioda, blok se smatra finalizovanim. Posle toga, skoro je nemoguće promeniti ga.

#### 2. Šta zapravo znači da je blok validan?

"Validan" znači da blok poštuje sva pravila protokola do najsitnijeg detalja. Kada validator dobije predloženi blok, on sprovodi niz provera, kao pedantni revizor. Evo ključnih provera:

1. Ispravna veza sa lancem: Da li se heš prethodnog bloka, zapisan u ovom novom bloku, zaista poklapa sa stvarnim hešom poslednjeg bloka u lancu? Blok mora da bude ispravan sledeći deo slagalice.

2. Autoritet predlagača: Da li je ovaj blok zaista potpisao validator koji je bio izabran da predloži blok u ovom specifičnom vremenskom slotu? Ne može bilo ko da predlaže blokove kad god poželi.

3. Validnost SVIH transakcija unutar bloka: Ovo je najvažniji deo. Validator proverava svaku pojedinačnu transakciju u bloku:

    - Digitalni potpis: Da li svaka transakcija ima validan potpis koji se poklapa sa javnim ključem pošiljaoca?

    - Stanje na računu: Da li pošiljalac ima dovoljno sredstava da izvrši transakciju i plati proviziju?

    - Jedinstvenost: Da li je neka od ovih transakcija već prethodno zabeležena na blokčejnu (prevencija "double-spending"-a)?

4. Poštovanje ostalih pravila: Da li blok ima ispravan vremenski pečat (timestamp)? Da li je unutar dozvoljene veličine? I tako dalje.

Ako bilo koja od ovih provera ne uspe, validator će smatrati blok nevažećim i neće glasati za njega.

#### 3. Šta se prvo desi? Dodavanje novog bloka u lanac ili transakcije unutar bloka?

Transakcije se uvek dese prve.

Blok ne može postojati bez transakcija, on je u suštini samo "paket" ili "kontejner" za transakcije.

Hajde da prođemo kroz ceo životni ciklus, korak po korak:

1. Korak 1: Kreiranje transakcija (Pisma se pišu)
    
    Sve počinje sa korisnicima. Ti, ja, i hiljade drugih ljudi kreiramo transakcije. Svako od nas potpiše svoju transakciju (npr. "šaljem 0.1 ETH Petru") i pošalje je u mrežu.

2. Korak 2: "Čekaonica" za transakcije - Mempool (Pisma u poštanskom sandučetu)
    
    Te transakcije ne idu odmah u blok. One odlaze u neku vrstu javne "čekaonice" koja se zove mempool (memory pool). Svaki čvor u mreži ima svoj mempool, gde čuva listu svih validnih, ali još nepotvrđenih transakcija koje je video.

3. Korak 3: Rudar/Validator bira transakcije (Poštar dolazi i kupi pisma)
    
    Kada dođe vreme da se kreira novi blok (npr. na svakih 10 minuta za Bitcoin), rudar ili validator koji je dobio to pravo pogleda u svoj mempool. On iz te "čekaonice" izabere grupu transakcija koje želi da uključi u svoj blok. Obično bira one sa najvećim provizijama, jer će te provizije biti deo njegove nagrade.

4. Korak 4: Formiranje i dodavanje bloka (Poštar pakuje pisma u torbu i kreće na put)
    
    Tek sada, kada je odabrao transakcije, rudar/validator ih "pakuje" u blok, dodaje sve potrebne informacije u zaglavlje (heš prethodnog bloka, nonce, itd.), i obavlja svoj zadatak konsenzusa (rešava PoW zagonetku ili potpisuje blok u PoS).
    Kada uspe, on taj kompletan blok (sa sve transakcijama unutra) objavljuje mreži. Tek u tom trenutku se "blok dodaje u lanac".

Dakle, redosled je:

Transakcije nastaju -> Čekaju u mempool-u -> Bivaju izabrane i upakovane u blok -> Blok se dodaje u lanac.

#### 4. Od čega zavisi provizija transakcije? Je l' od same vrednosti transakcije? Da li postoji procenat ili je fiksna transakcija?

U svetu blokčejna, provizija transakcije (transaction fee) skoro nikad ne zavisi od novčane vrednosti koju šalješ!

To je jedna od najvećih razlika u odnosu na tradicionalne bankarske sisteme. Mogao bi da pošalješ ekvivalent od 100 miliona evra, a da platiš manju proviziju od nekoga ko šalje 10 evra.

Od čega onda zavisi provizija?

Provizija zavisi od dva glavna faktora:

1. "Veličina" ili složenost transakcije (u bajtovima ili "gasu")

    Zamisli da je blok jedan kamion sa ograničenim tovarnim prostorom. Rudar (vozač kamiona) želi da maksimalno zaradi od tog prostora.

    - Jednostavna transakcija ("šaljem X novčića sa adrese A na adresu B") je kao mali, lagan paket. Zauzima malo prostora u kamionu.

    - Složena transakcija (npr. interakcija sa pametnim ugovorom koja pokreće više operacija) je kao ogroman, težak paket. Zauzima mnogo više prostora.

    Rudaru nije bitno šta je unutar paketa (da li je dijamant od milion evra ili kutija peska), već koliko prostora paket zauzima. Zato se provizija obično računa po jedinici "prostora" – na primer, po bajtu (per-byte basis). Što ti je transakcija veća u bajtovima, to ćeš platiti veću proviziju da bi je rudar uključio u svoj blok.

    Na platformama kao što je Ethereum, ovo se meri u "gasu". Složenije operacije "troše" više gasa, pa je i provizija veća.

2. Zagušenost mreže (ponuda i potražnja)

    Zamisli sada da na utovar čeka stotine paketa (transakcija u mempool-u), a u kamion (blok) može da stane samo 50. Vozač kamiona (rudar) će, naravno, prvo utovariti one pakete čiji su vlasnici ponudili najviše novca za prevoz.

    - Ako je mreža zagušena (mnogo ljudi šalje transakcije), stvara se velika potražnja za ograničenim prostorom u bloku. Tada moraš da ponudiš veću proviziju da bi "preskočio red" i ubedio rudara da baš tvoju transakciju uključi u sledeći blok.

    - Ako je mreža rasterećena, možeš proći i sa mnogo manjom provizijom, jer nema konkurencije.

Da li je procenat ili fiksna?

Nije ni jedno ni drugo. To je dinamična tržišna cena koju ti kao korisnik sam postavljaš. Tvoj kripto-novčanik ti obično pomogne tako što ti predloži iznos provizije na osnovu trenutne zagušenosti mreže (obično ponudi opcije: sporo, prosečno, brzo).

Dakle, provizija nije procenat vrednosti koju šalješ, već cena koju si spreman da platiš za prostor u bloku na otvorenom tržištu.

#### 5. Šta je gas kod Euthereuma i kako se on računa, odnosno, od čega on zavisi?

Gas je jedinica mere za računarski rad na Ethereum mreži. 

Zamisli ga kao benzin za auto. Da bi auto išao, mora da troši benzin. Da bi se izvršila bilo kakva operacija na Ethereumu, mora da se "potroši" gas.

Šta je zapravo "gas"?

Svaka operacija na Ethereumu, od najprostije do najkompleksnije, ima fiksnu cenu izraženu u jedinicama gasa. Na primer (vrednosti su uprošćene):

- Slanje ETH sa jednog naloga na drugi: 21,000 gasa

- Sabiranje dva broja unutar pametnog ugovora: 3 gasa

- Čuvanje podatka na blokčejnu: 20,000 gasa

Ovaj sistem postoji da bi se sprečilo da neko zlonamerno ili slučajno optereti mrežu beskonačnim petljama ili previše složenim operacijama. Svaki računarski korak ima svoju cenu, i ti kao korisnik moraš da platiš za taj rad.

Kako se računa provizija i od čega zavisi?

E tu dolazimo do ključne stvari. Provizija se ne plaća u gasu, već u ETH. Ukupna provizija koju platiš zavisi od dve stvari koje ti kao korisnik postavljaš pre slanja transakcije:

1. Gas Limit (Limit gasa): Ovo je MAKSIMALAN broj jedinica gasa koji si spreman da potrošiš na svoju transakciju. To je kao da kažeš: "Spreman sam da platim za najviše 50,000 jedinica gasa za ovu operaciju." 

    - Ako tvoja transakcija potroši manje od limita (npr. 30,000), ostatak (20,000) ti se vraća. 

    - Ako tvoja transakcija zahteva više gasa od tvog limita, operacija neće uspeti ("out of gas" greška), ali ćeš svejedno platiti proviziju za rad koji je izvršen do trenutka prekida! 

2. Gas Price (Cena gasa): Ovo je cena koju si spreman da platiš po jednoj jedinici gasa.  Izražava se u malim jedinicama ETH-a (zvanim Gwei). Ovo je deo koji funkcioniše kao aukcija.

    - Ako je mreža zagušena, moraš ponuditi veću cenu gasa da bi ubedio validatore da tvoju transakciju uključe u blok pre ostalih. 

    - Ako mreža nije zagušena, možeš proći sa nižom cenom.

Formula za proviziju je:

Ukupna provizija (u ETH) = Broj potrošenih jedinica gasa * Cena gasa (koju si ponudio)

## BC.10. Стање блокчејна: модел заснован на трансакцијама и модел заснован на рачунима.

Stanje blokčejna (blockchain state) je jednostavno trenutni snimak svih podataka: balansi, vlasništvo, stanje pametnih ugovora, itd.. To je odgovor na pitanje "Ko šta ima u ovom trenutku?". Postoje dva fundamentalno različita načina na koja blokčejn može da prati ovo stanje.

### 1. Model zasnovan na transakcijama (UTXO Model)

Ovaj model je najpoznatiji po svojoj upotrebi u Bitcoinu. Umesto da prati stanje na računima (balanse), ovaj model prati nepotrošene izlaze transakcija (Unspent Transaction Outputs - UTXO).

Kako funkcioniše?

Zaboravite na ideju da imate "račun" sa jednim brojem. Umesto toga, vaš "balans" je zbir svih malih, pojedinačnih transakcija koje ste primili, a još niste potrošili. Svaki taj nepotrošeni iznos je jedan UTXO.

- Analogija sa gotovinom: Zamislite da je vaš novčanik UTXO model. U njemu nemate ispisan jedan broj (npr. 580 dinara). Umesto toga, imate kolekciju pojedinačnih novčanica i kovanica (UTXO-a): jednu novčanicu od 500 din, jednu od 50, jednu od 20 i jednu od 10 dinara.

    - Kada želite da platite kafu od 180 dinara, ne možete samo "oduzeti 180". Morate da uzmete novčanicu od 500 dinara (jedan UTXO) , date je prodavcu, i on vam vrati kusur od 320 dinara (što je za vas novi UTXO).

    - Stara novčanica od 500 dinara je sada "potrošena" i više ne postoji u vašem novčaniku. Zamenjena je novom od 320 dinara.

Tako funkcioniše Bitcoin: svaka transakcija troši stare UTXO-e i stvara nove.

Prednosti: Veća transparentnost jer se može pratiti "poreklo" svakog novčića, i potencijalno veća privatnost.

Mane: Manje je intuitivno i računarski je složenije za programiranje pametnih ugovora.

### 2. Model zasnovan na računima (Account-based Model)

Ovaj model koriste Ethereum i većina platformi za pametne ugovore. Mnogo je sličniji tradicionalnom bankarskom sistemu.

Kako funkcioniše?

Blokčejn direktno prati stanje svakog računa (adrese) kao jedan broj – balans.

- Kada pošaljete transakciju, sistem jednostavno oduzme iznos sa vašeg balansa i doda ga na balans primaoca. To je to. Stanje se direktno ažurira.

- Analogija sa bankovnim računom: Ovo je kao kada pogledate stanje na svom bankovnom računu. Vidite jedan broj. Kada platite karticom, taj broj se smanji. Kada primite platu, on se poveća. Sistem ne pamti da se vaša plata sastojala od jedne novčanice od 50,000 i jedne od 20,000; on samo zna da je vaš balans sada veći za 70,000.

Prednosti: Mnogo je jednostavnije i intuitivnije. Provera balansa je trenutna. Ovaj model je daleko efikasniji za izvršavanje složenih pametnih ugovora jer programeri ne moraju da se bave logikom biranja i kombinovanja UTXO-a.

Mane: Teže je pratiti istoriju pojedinačnog novčića jer se svi "stapaju" u jedan balans (sredstva su "fungible" - zamenjiva).

Ukratko:

- UTXO (Bitcoin): Kao da plaćaš gotovinom – pratiš svaku novčanicu.

- Account (Ethereum): Kao da plaćaš karticom – pratiš samo konačno stanje na računu.

## BC.11. Структура блокчејн ланца.

Podaci na blokčejnu nisu samo nabacani, već su organizovani u blokove koji se hronološki dodaju jedan na drugi, formirajući lanac.

Ključ koji sve ovo povezuje je kriptografski heš. Svaki blok ima dva izuzetno važna atributa koja ga čine delom lanca:

1. Heš bloka (Block Hash): Ovo je jedinstveni "digitalni otisak" tog bloka, izračunat na osnovu njegovog sadržaja (preciznije, zaglavlja). Ako se i najmanji delić podatka u bloku promeni, njegov heš se drastično menja.

2. Heš prethodnog bloka (Previous Hash): Ovo je "lepak" koji drži lanac na okupu. Svaki novi blok u svom zaglavlju mora da sadrži heš bloka koji je došao neposredno pre njega.

Ova struktura b(i).prev_hash = HASH(b(i-1)) stvara neraskidivu zavisnost između blokova.

Kako ova struktura garantuje nepromenljivost?

Ova genijalna struktura čini lanac otpornim na neovlašćene izmene. Zamisli da zlonamerni haker želi da promeni neku staru transakciju u, recimo, Bloku 100.

1. Promena podatka: Haker menja podatak u Bloku 100.

2. Menja se heš: Zbog te promene, heš Bloka 100 se potpuno menja.

3. Puca veza: Sada, Blok 101, koji u sebi sadrži stari heš Bloka 100, više nije validan. Njegova veza sa prethodnim blokom je prekinuta.

4. Domino efekat: Pošto je Blok 101 sada neispravan, njegov heš je takođe nevažeći, što prekida vezu sa Blokom 102, i tako redom, sve do kraja lanca.

5. Mreža odbacuje promenu: Kada bilo koji čvor u mreži pokuša da verifikuje ovu izmenjenu verziju lanca, odmah će primetiti nedoslednost – da se heš Bloka 100 ne poklapa sa onim što je zapisano u Bloku 101. Mreža će automatski odbaciti ovu izmenjenu verziju kao nevažeću.

Da bi napad uspeo, haker bi morao da ponovo izračuna heševe za Blok 100 i sve blokove posle njega, i to brže od cele ostatka mreže, što je praktično nemoguće.

## BC.12. Процесирање трансакције.

Procesiranje transakcije je put koji ona pređe od trenutka kada je kreiraš do trenutka kada postane trajni deo blokčejna. Možemo ga podeliti u dva glavna dela: životni ciklus transakcije i životni ciklus bloka u koji ona ulazi.

### Deo 1: Životni ciklus transakcije

1. Kreiranje i potpisivanje: Sve počinje kada korisnik kreira transakciju u svom digitalnom novčaniku (npr. "šaljem 1 BTC na adresu X"). Korisnik je potpisuje svojim privatnim ključem.

2. Emitovanje i propagacija: Korisnik šalje potpisanu transakciju jednom od čvorova u mreži. Taj čvor prvo proverava osnovnu validnost transakcije (da li je potpis ispravan, da li je format dobar). Ako je sve u redu, on je prosleđuje svojim susednim čvorovima, koji je zatim prosleđuju svojim susedima, i tako se transakcija brzo širi mrežom kao glasina.

3. Ulazak u Mempool: Svaki čvor koji primi i verifikuje transakciju dodaje je u svoju "čekaonicu" – mempool. Mempool je skup svih validnih, ali još uvek nepotvrđenih transakcija koje čekaju da budu uključene u blok.

### Deo 2: Životni ciklus bloka

1. Formiranje bloka: Rudar ili validator, kome je došao red da kreira novi blok, bira transakcije iz svog mempool-a. On ih pakuje u novi, kandidat-blok.

2. Rešavanje konsenzusa: Rudar sada obavlja "posao" – rešava Proof-of-Work zagonetku da bi pronašao validan heš za svoj blok.

3. Emitovanje bloka: Kada rudar uspešno "izrudi" blok, on ga objavljuje celoj mreži.

4. Validacija i prihvatanje bloka: Ostali čvorovi u mreži primaju ovaj novi blok. Oni sada vrše potpunu proveru (validaciju bloka):

    - Da li je heš bloka ispravan (da li je PoW zagonetka rešena)?

    - Da li se blok ispravno nadovezuje na prethodni blok u lancu?

    - Da li su sve transakcije unutar bloka validne (da pošiljaoci imaju dovoljno sredstava, da nema dvostrukog trošenja itd.)? 

5. Dodavanje u lanac: Ako blok prođe sve provere, svaki čvor ga dodaje u svoju kopiju blokčejna. U tom trenutku, sve transakcije unutar tog bloka se smatraju potvrđenim. One su sada zvanično deo nepromenljive istorije.

## BC.13. Садржај трансакције и блока.

Transakcija je osnovna operacija na blokčejnu. Iako se detalji mogu razlikovati, svaka transakcija obično sadrži sledeće elemente:

- Ulazi (Inputs): Ovo definiše odakle novac dolazi. U UTXO modelu (Bitcoin), ovo su reference na prethodne nepotrošene transakcije (UTXO-e) koje pošiljalac koristi kao izvor sredstava.

- Izlazi (Outputs): Ovo definiše gde novac ide. Sadrži adresu primaoca i tačan iznos koji mu se šalje.

- Heš transakcije (Transaction ID): Svaka transakcija ima svoj jedinstveni digitalni otisak, koji služi kao njen identifikator.

- Digitalni potpis: Kriptografski dokaz, kreiran pomoću privatnog ključa pošiljaoca, koji potvrđuje da je on zaista odobrio transakciju.

Blok je struktura podataka koja sadrži grupu transakcija. Svaki blok se sastoji iz dva glavna dela: tela i zaglavlja.

Telo bloka sadrži sve transakcije koje su uključene u taj blok. Sastoji se od:

- Brojač transakcija: Jednostavan broj koji kaže koliko transakcija ima u bloku.

- Lista transakcija: Kompletni podaci za svaku transakciju koja je potvrđena u ovom bloku. One su često organizovane u posebnu strukturu zvanu Merkle drvo, o kojoj ćemo pričati u sledećem pitanju.

Zaglavlje je "lična karta" bloka. Sadrži ključne metapodatke i mnogo je manje od tela bloka. Ono je deo koji se hešira da bi se dobio ID bloka. Njegovi ključni delovi su:

- Verzija (Version): Tehnički podatak koji označava koja pravila (verziju protokola) blok prati.

- Heš prethodnog bloka (Previous Hash): Heš bloka koji je došao pre ovog u lancu. Ovo je ključni element koji povezuje blokove.

- Merkle koren (Merkle Root Hash): Jedan jedini heš koji predstavlja kriptografski sažetak SVIH transakcija u telu bloka. Omogućava brzu proveru integriteta transakcija bez potrebe za preuzimanjem celog tela bloka.

- Vremenski pečat (Timestamp): Tačno vreme kada je blok kreiran (izrudar).

- Težina (Difficulty Target / nBits): Broj koji definiše koliko je teška bila PoW zagonetka koju je rudar morao da reši.

- Nonce: Slučajni broj koji je rudar pronašao kao rešenje PoW zagonetke.

## BC.14. Меркле-дрво.

Merkle drvo (Merkle Tree) je struktura podataka koja se koristi da se sve transakcije u jednom bloku sažmu u jedan jedini heš - Merkle koren (Merkle Root). Zamisli ga kao piramidu od heševa.

Kako se gradi?

Proces je jednostavan i ponavlja se dok se ne stigne do vrha (korena). Krenimo od dna sa, na primer, 4 transakcije (Tx1, Tx2, Tx3, Tx4):

1. Dno (Lišće): Prvo se uzme svaka pojedinačna transakcija i za nju se izračuna heš. Ovi heševi (H1, H2, H3, H4) formiraju dno, odnosno "lišće" drveta.

2. Srednji nivo (Grane): Zatim se ti heševi grupišu u parove. Heševi H1 i H2 se spoje i onda se za taj spojeni podatak izračuna novi heš, H12. Isto se uradi za H3 i H4, što daje H34.

3. Vrh (Koren): Proces se ponavlja. Sada se spoje heševi H12 i H34 i za njih se izračuna finalni heš - Merkle koren (Merkle Root).

Ovaj jedan, finalni heš se upisuje u zaglavlje bloka i on predstavlja digitalni otisak svih transakcija u tom bloku.

Zašto je ovo korisno? Dva su ključna razloga.

1. Efikasnost i Integritet

    Umesto da se u zaglavlje bloka stavljaju heševi svih transakcija, stavlja se samo jedan, mali heš – Merkle koren. Ovo štedi ogroman prostor.

    Najvažnije, ako bi neko pokušao da promeni i najmanji delić bilo koje transakcije na dnu (npr. iznos u Tx3), heš H3 bi se promenio. To bi onda promenilo heš H34, što bi na kraju promenilo i sam Merkle koren. Dakle, proverom samo jednog heša (Merkle korena), može se momentalno utvrditi da li je ceo skup transakcija menjan.

2. Brza provera članstva (Merkle Proof)

    Ovo je prava magija Merkle drveta. Zamisli da želiš da dokažeš da se tvoja transakcija (Tx3) nalazi u bloku koji ima milion transakcija. Ne moraš da preuzmeš ceo blok! 

    Dovoljno je da imaš samo nekoliko informacija:

    - Heš tvoje transakcije (H3)

    - Heš "bratskog" čvora (H4)

    - Heš "rođačkog" čvora na višem nivou (H12)

    Sa ove tri informacije, bilo ko može da izračuna H34 (spajanjem H3 i H4), zatim da spoji H34 sa H12 i izračuna Merkle koren. Ako se taj izračunati koren poklopi sa onim koji je zapisan u zaglavlju bloka, to je matematički dokaz da se tvoja transakcija nalazi u tom bloku. Ovo je izuzetno važno za "lake klijente" (lightweight nodes) koji nemaju resurse da čuvaju ceo blokčejn.

### Digresija

#### 1. Kako se računaju heševi za transakcije? Je l' to Transaction ID?

Heš transakcije je upravo njen Transaction ID (TxID).

Računa se tako što se uzme kompletan sadržaj jedne transakcije – svi njeni podaci, kao što su ulazi, izlazi, iznosi itd. – i sve to se kao jedan dugačak niz podataka provuče kroz heš funkciju (npr. SHA-256).

Rezultat te operacije je jedinstveni, fiksne dužine heš, koji služi kao nepogrešivi identifikator te transakcije. Zato, ako bi iko pokušao da promeni i najmanju sitnicu u transakciji, njen ID bi se potpuno promenio.

#### 2. Je l' Merkle drvo binarno?

Da, jeste. Merkle drvo koje se koristi u blokčejnu je binarno stablo (binary tree).

To znači da se heševi uvek grupišu u parove. Svaki "čvor" u drvetu koji nije list ima tačno dve "grane" koje vode do dva čvora ispod njega.

A šta se dešava ako imamo neparan broj transakcija, na primer 5?

Protokol ima jednostavno rešenje za to: uzme poslednju transakciju (Tx5) i duplira njen heš da bi napravio veštački par. Na taj način uvek imamo paran broj elemenata za heširanje u svakom koraku, i struktura ostaje savršeno binarna.

## BC.15. Паметни уговори.

Pametni ugovor, uprkos imenu, nije pravni dokument, već 

kompjuterski program koji se čuva i izvršava na blokčejnu. Njegova glavna svrha je da automatski sprovede uslove nekog dogovora kada se ispune unapred definisani uslovi.

Radi po jednostavnom "AKO-ONDA" (IF-THEN) principu:
AKO se desi događaj X, ONDA automatski izvrši akciju Y.

Ovaj proces eliminiše potrebu za posrednikom (kao što je banka, advokat ili notar) koji bi proveravao uslove i sprovodio dogovor. Poverenje nije u osobi ili instituciji, već u kodu koji je javan i nepromenljiv.

Ključne karakteristike

- Automatizovani i samostalni: Jednom postavljeni, pametni ugovori se izvršavaju automatski kada se uslovi ispune, bez ičije intervencije.

- Nepromenljivi (Immutable): Jednom kada se pametni ugovor postavi na blokčejn, njegov kod se generalno ne može menjati. Ovo osigurava da se pravila igre ne mogu promeniti usred partije.

- Transparentni: Kod pametnog ugovora je javan i vidljiv svima na blokčejnu. Svako može da proveri pravila pre nego što odluči da interaguje sa ugovorom.

- Decentralizovani: Izvršavaju se na svim čvorovima u mreži, tako da ne zavise od jednog servera.

Kako rade?

1. Programiranje: Programeri pišu kod pametnog ugovora u specijalizovanim jezicima kao što je Solidity (za Ethereum).

2. Postavljanje (Deployment): Kod se zatim postavlja na blokčejn putem transakcije. Nakon toga, ugovor dobija svoju jedinstvenu adresu i postaje aktivan.

3. Izvršavanje: Korisnici mogu da "pozovu" funkcije unutar pametnog ugovora slanjem transakcija na njegovu adresu. Svaki čvor u mreži pokreće kod ugovora unutar svog Ethereum Virtual Machine (EVM) da bi izračunao rezultat i ažurirao stanje na blokčejnu.

## BC.16. Скалабилност блокчејна, ролапови, L1/L2.

Problem Skalabilnosti i "Trijlema Blokčejna"

Kao što smo spomenuli, skalabilnost je najveća boljka blokčejna. Mreže kao što su Bitcoin i Ethereum su spore; mogu da obrade samo mali broj transakcija u sekundi. Kada mnogo ljudi želi da koristi mrežu, ona se zaguši, a provizije postaju astronomske.

Ovo je posledica takozvane "Trijleme Blokčejna". To je ideja da je izuzetno teško napraviti blokčejn koji istovremeno postiže tri ključne osobine:

1. Decentralizaciju (nema centralne kontrole)

2. Sigurnost (otpornost na napade)

3. Skalabilnost (veliki broj transakcija u sekundi)

Obično morate žrtvovati jednu da biste poboljšali druge dve. Bitcoin, na primer, žrtvuje skalabilnost zarad vrhunske decentralizacije i sigurnosti.

Rešenja: Layer 1 (L1) vs. Layer 2 (L2)

Postoje dva glavna pristupa rešavanju ovog problema:

- Layer 1 (L1) rešenja: Ovo su promene na samom, osnovnom blokčejnu. Na primer, prelazak Ethereuma sa PoW na PoS je L1 rešenje jer menja fundamentalni konsenzus mehanizam da bi bio brži i efikasniji.

- Layer 2 (L2) rešenja: Ovo je mnogo popularniji pristup. Umesto da se menja spori, ali sigurni osnovni lanac (L1), grade se posebni, brzi sistemi koji rade "iznad" njega. Ideja je: obavljajmo hiljade transakcija brzo i jeftino na L2, a onda samo periodično sačuvajmo "sažetak" tih transakcija na sigurni L1. Time dobijamo najbolje iz oba sveta: brzinu L2 i sigurnost L1.

Rolapovi su trenutno vodeća L2 tehnologija. Oni rade tako što "urolaju" ili spakuju stotine transakcija u jednu jedinu transakciju, koju zatim objave na L1. Ovo drastično smanjuje troškove i povećava propusnu moć. Postoje dve glavne vrste:

1. Optimistic Rollups

    Oni se zovu "optimistični" jer optimistično pretpostavljaju da su sve transakcije u paketu validne i objavljuju ih na L1 bez trenutnog dokaza. Nakon objavljivanja, počinje "period za žalbe" (obično 7 dana). Bilo ko može da posmatra transakcije i, ako primeti prevaru, može da podnese "dokaz o prevari" (fraud proof). Ako se dokaz potvrdi, lažna transakcija se poništava, a prevarant gubi svoj ulog.

    - Prednost: Lako se prave i kompatibilni su sa Ethereumom.

    - Mana: Morate čekati 7 dana da biste sigurno povukli novac sa L2 na L1.

2. Zero-Knowledge (ZK) Rollups

    Ovi rolapovi koriste naprednu kriptografiju zvanu "dokaz bez znanja" (zero-knowledge proof). Pre nego što objave paket transakcija na L1, oni generišu kriptografski dokaz (ZK-proof) koji matematički garantuje da su sve transakcije unutar paketa validne. L1 samo treba da proveri taj jedan, mali dokaz, što je izuzetno brzo. Nema potrebe za "optimističkim" pretpostavkama.

    - Prednost: Vrhunska sigurnost i skoro trenutno povlačenje novca na L1, jer nema perioda za žalbe.

    - Mana: Tehnologija je mnogo složenija i teža za implementaciju.

### Digresija

#### 1. Šta je "sažetak" transakcija koji se šalje na L2? Je l' to Merkle koren?

Merkle koren je ključan deo tog sažetka, ali nije jedini.

Kada L2 objavi "sažetak" na L1, on zapravo objavljuje dve stvari:

1. Novi "koren stanja" (State Root): Ovo je jedan jedini heš (veoma sličan Merkle korenu) koji predstavlja kriptografski otisak kompletnog stanja celog L2 sistema nakon što su sve transakcije iz paketa izvršene. Ako se i najmanji balans promeni, ovaj koren se menja.

2. Kompresovani podaci o transakcijama: Ovo je najvažniji deo. Rolap ne šalje samo heš; on šalje i veoma kompresovane podatke iz svih transakcija u paketu (npr. samo iznos, adrese pošiljaoca i primaoca, bez potpisa i ostalih podataka).

Zašto su oba dela važna? Koren stanja (1) dokazuje šta je novi ishod, a kompresovani podaci (2) pružaju dostupnost podataka (data availability), omogućavajući bilo kome da, gledajući samo L1, može da rekonstruiše i proveri šta se desilo na L2. Ovo sprečava L2 operatera da laže ili sakrije podatke.

#### 2. Kako da "odrolamo" urolanu transakciju i vidimo originale?

"Jedna jedina transakcija" na L1 nije kao zaključan sef u koji ne može da se uđe. Ona je više kao ZIP fajl.

Unutar te jedne L1 transakcije se nalaze kompresovani podaci svih originalnih L2 transakcija. Puni, nekompresovani detalji (ko, kome, koliko, šta se poziva u pametnom ugovoru) se čuvaju i izvršavaju na samoj L2 mreži.

Podaci koji se objave na L1 služe kao javna oglasna tabla ili sigurnosna kopija. Bilo ko (ili bilo koji softver) može da pročita te kompresovane podatke sa L1 i da ih iskoristi da nezavisno proveri i rekonstruiše stanje na L2.

Dakle, ti ne "odrolavaš" transakciju na L1. Ti koristiš podatke objavljene na L1 da bi potvrdio šta se desilo na L2. Ovo osigurava da L2 mreža ostane transparentna i sigurna, jer se oslanja na L1 kao na javni i nepromenljivi zapis.

#### 3. Kako ZKP dokazuje da su transakcije validne?

Dokaz bez znanja (Zero-Knowledge Proof - ZKP) omogućava jednoj strani (Dokazivaču) da dokaže drugoj strani (Verifikatoru) da je neka tvrdnja tačna, a da pritom ne otkrije nikakve informacije osim same činjenice da je tvrdnja tačna.

U kontekstu ZK-rolapova:

- Dokazivač (Prover) = L2 operater.

- Verifikator (Verifier) = Pametni ugovor na L1.

- Tvrdnja: "Počeo sam sa stanjem A. Zatim sam validno izvršio ovih 500 transakcija jednu po jednu (svaki potpis je ispravan, niko nije potrošio novac koji nema, itd.) i završio sam sa stanjem B."

Proces izgleda ovako:

1. "Krug" (Circuit): Tvrdnja se pretvara u ogroman matematički "krug" ili program. Taj program će dati tačan rezultat samo i isključivo ako je svaki korak u tvrdnji bio ispravan.

2. Generisanje dokaza: L2 operater pokreće ovaj program na moćnom računaru. Program kao izlaz ne daje samo "tačno" ili "netačno", već generiše jedan mali, kompaktni kriptografski dokaz (ZK-proof). Taj dokaz je kao magični pečat koji se može stvoriti samo ako je cela tvrdnja bila 100% tačna.

3. Verifikacija dokaza: L2 operater pošalje taj mali ZK-proof na L1. Pametni ugovor na L1 ne mora da ponovo izvršava svih 500 transakcija. On samo izvrši jednu brzu matematičku proveru samog dokaza. Ako provera prođe, on sa matematičkom sigurnošću zna da je cela tvrdnja bila tačna.

## BC.17. ERC20 токени, ERC721 токени.

ERC je skraćenica za "Ethereum Request for Comment". To su tehnički standardi koje je predložila zajednica da bi se osiguralo da različiti tokeni i aplikacije na Ethereum mreži mogu međusobno da "razgovaraju" bez problema. Dva najvažnija standarda su ERC20 i ERC721.

### ERC20: Zamenljivi (Fungible) tokeni

ERC20 je standard za kreiranje zamenljivih (fungible) tokena.

Šta znači "zamenljiv"? To znači da je svaka jedinica tokena identična i ima istu vrednost kao bilo koja druga jedinica istog tokena.

- Analogija sa novcem: Novčanica od 1000 dinara u mom džepu je potpuno ista i vredi isto kao novčanica od 1000 dinara u tvom džepu. Možemo ih zameniti i ništa se neće promeniti. Zbog toga je novac zamenljiv.

ERC20 tokeni se ponašaju kao novac. Zato se ovaj standard koristi za kreiranje:

- Kriptovaluta (npr. Shiba Inu, Chainlink, Tether su ERC20 tokeni)

- Lojalti poena

- Glasačkih prava u nekoj organizaciji

Tehnički, svaki ERC20 ugovor mora da ima standardni set funkcija kao što su balanceOf() (proveri stanje), transfer() (pošalji tokene) i approve() (dozvoli nekome da potroši tvoje tokene). Ovo omogućava da svaki novčanik ili menjačnica zna kako da radi sa bilo kojim ERC20 tokenom bez dodatnog programiranja. 

### ERC721: Nezamenljivi (Non-Fungible) tokeni (NFT)

ERC721 je standard za kreiranje nezamenljivih (non-fungible) tokena, svetu mnogo poznatijih kao NFT (Non-Fungible Token).

Šta znači "nezamenljiv"? To znači da je svaki token jedinstven, unikatan i ne može se zameniti za drugi. Svaki NFT ima svoj jedinstveni ID i svoje specifične karakteristike.

- Analogija sa nekretninama ili umetnošću: Tvoja kuća na jednoj adresi nije ista kao moja kuća na drugoj adresi, iako su obe kuće. Slika "Mona Liza" je unikatna i ne može se zameniti za sliku "Zvezdana noć", iako su obe slike. One su nezamenljive.

ERC721 tokeni služe da predstave vlasništvo nad jedinstvenom digitalnom ili čak fizičkom imovinom. Koriste se za:

- Digitalnu umetnost i kolekcionarske predmete (npr. CryptoPunks, Bored Ape Yacht Club)

- Predmete u video igrama (jedinstveni mač ili oklop)

- Ulaznice za događaje (ulaznica za sedište A5 nije ista kao za B12)

- Digitalni identitet i sertifikate

- Vlasničke listove za nekretnine

Tehnički, ključna stvar kod ERC721 je što svaki token ima jedinstveni tokenId, a ugovor prati ko je vlasnik (ownerOf) svakog pojedinačnog tokena.

## BC.Rezime

1. Osobine blokčejna: Glavne karakteristike su decentralizacija (nema glavnog šefa), nepromenljivost (podaci se ne mogu menjati), transparentnost i sigurnost zasnovana na kriptografiji.

2. Prednosti i mane: Prednosti su veća sigurnost, efikasnost i eliminacija posrednika. Mane su pre svega problemi sa skalabilnošću (brzinom) i ogromna potrošnja energije kod nekih sistema (PoW).

3. Primene: Nije samo za kriptovalute. Koristi se u finansijama, lancima snabdevanja, glasanju, zdravstvu, i mnogim drugim industrijama.

4. Izazovi za usvajanje: Glavne prepreke su nedostatak jasnih zakona (regulativa), problemi sa skalabilnošću, troškovi implementacije i nedostatak komunikacije između različitih blokčejna (interoperabilnost).

5. Osnovni elementi: Blokčejn čini pet stubova: decentralizovana mreža (računari), kriptografija (matematika), distribuirani konsenzus (dogovor), knjiga transakcija (zapis) i pametni ugovori (automatizacija).

6. Kriptografski elementi: Dva ključna alata su heš funkcije (stvaraju digitalni otisak i povezuju blokove) i kriptografija sa javnim ključem (omogućava digitalne potpise za potvrdu vlasništva).

7. Problem distribuiranog konsenzusa: Klasični "Problem vizantijskih generala" – kako postići dogovor u mreži gde ne možeš svima verovati.

8. Proof of Work (PoW): Rešenje konsenzusa koje koristi Bitcoin. Rudari se takmiče u rešavanju složene matematičke zagonetke. Ko prvi reši, dodaje blok. Sigurno, ali sporo i energetski veoma zahtevno.

9. Proof of Stake (PoS): Alternativa koju koristi novi Ethereum. Validatori ulažu (stake) svoj novac kao zalog za pošten rad. Ko će dodati blok se bira na osnovu uloga. Mnogo efikasnije, ali sa potencijalnim rizikom centralizacije.

10. Stanje blokčejna (dva modela):

    - UTXO model (Bitcoin): Kao gotovina u novčaniku; pratiš svaku pojedinačnu "novčanicu".

    - Account model (Ethereum): Kao bankovni račun; pratiš samo konačni balans.

11. Struktura lanca: Blokovi su povezani u lanac tako što svaki novi blok sadrži heš prethodnog bloka. Ovo stvara nepromenljivi, hronološki zapis.

12. Procesiranje transakcije: Put transakcije: kreiranje -> slanje u "čekaonicu" (mempool) -> rudar je bira i pakuje u blok -> blok se dodaje u lanac i transakcija je potvrđena.

13. Sadržaj bloka i transakcije: Blok se sastoji od zaglavlja (metadata, heševi) i tela (lista transakcija). Transakcija sadrži ulaze, izlaze, iznos i potpis.

14. Merkle drvo: Pametna struktura podataka koja sve transakcije u bloku sažima u jedan heš (Merkle root). Omogućava brzu proveru i štedi prostor.

15. Pametni ugovori: Programi na blokčejnu koji automatski izvršavaju zadatke po principu "AKO se desi X, ONDA uradi Y". Omogućavaju decentralizovane aplikacije (dApps).

16. Skalabilnost (L1/L2, Rolapovi): Problem sporosti se rešava L2 rešenjima koja rade "iznad" glavnog L1 lanca. Rolapovi (Optimistic i ZK) su ključna L2 tehnologija koja pakuje stotine transakcija u jednu.

17. Tokeni (ERC20 i ERC721): Standardi za kreiranje imovine na Ethereumu.

    - ERC20: Za zamenljive stvari (novac, poeni). Kao dinar.

    - ERC721: Za jedinstvene, nezamenljive stvari (NFT). Kao Mona Liza.

## BC.Zadaci

### 1. Имплементирати паметан уговор PetStore.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title PetStore
 * @dev Pametni ugovor za prodavnicu kućnih ljubimaca.
 */
contract PetStore {

    // 1. Struktura podataka za predstavljanje kućnih ljubimaca
    struct Pet {
        uint id;
        string name;
        uint price; // Cena u Wei
        address owner;
        bool forSale;
    }

    // 3. Promenljive za upravljanje prodavnicom
    address public storeOwner;
    uint public petCounter;

    // 2. Mapa za čuvanje kućnih ljubimaca
    mapping(uint => Pet) public pets;

    // 6. Događaji
    event PetAdded(uint id, string name, uint price);
    event PetBought(uint id, address indexed oldOwner, address indexed newOwner, uint price);

    constructor() {
        storeOwner = msg.sender;
    }

    /**
     * @dev Dodaje novog kućnog ljubimca u prodavnicu. Samo vlasnik prodavnice.
     * @param _name Ime novog ljubimca.
     * @param _price Cena novog ljubimca u Wei.
     */
    function addPet(string memory _name, uint _price) public {
        // 5. Kontrola pristupa
        require(msg.sender == storeOwner, "Only the store owner can add pets.");
        
        petCounter++;
        uint newPetId = petCounter;
        
        pets[newPetId] = Pet({
            id: newPetId,
            name: _name,
            price: _price,
            owner: storeOwner,
            forSale: true
        });
        
        emit PetAdded(newPetId, _name, _price);
    }

    /**
     * @dev Vraća detalje o kućnom ljubimcu na osnovu ID-ja.
     * @param _id ID ljubimca za pretragu.
     */
    function getPet(uint _id) public view returns (Pet memory) {
        return pets[_id];
    }

    /**
     * @dev Omogućava korisniku da kupi ljubimca slanjem tačnog iznosa.
     * @param _id ID ljubimca koji se kupuje.
     */
    function buyPet(uint _id) public payable {
        Pet storage petToBuy = pets[_id];
        
        // Provera uslova
        require(petToBuy.id != 0, "Pet does not exist.");
        require(petToBuy.forSale, "This pet is not for sale.");
        require(msg.value == petToBuy.price, "Incorrect amount of Ether sent.");

        address previousOwner = petToBuy.owner;

        // Ažuriranje stanja
        petToBuy.owner = msg.sender;
        petToBuy.forSale = false;
        
        emit PetBought(_id, previousOwner, msg.sender, msg.value);

        // Slanje novca
        (bool sent, ) = payable(previousOwner).call{value: msg.value}("");
        require(sent, "Failed to send Ether to the owner.");
    }
}
```
