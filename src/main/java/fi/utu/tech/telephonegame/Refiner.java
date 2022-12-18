package fi.utu.tech.telephonegame;

import java.util.Random;

public class Refiner {

	private static final String[] conjunctions  = (
			"että, jotta, koska, kun, jos, vaikka, kunnes, mikäli, ja")
			.split(",");


	//Initialize arrays of words to be used in refining the message
	private static final String[] animals = (
			"karhu, koira, kissa, kilpikonna, kani, käärme, hevonen, lumikko, gepardi, leijona, tiikeri, kirahvi, sarvikuono, tietopussihiiri, hiirihamsteri, gnuu, gorilla, apina, paviaani, hylje, norsu, sika, lehmä, lammas, varaani, iguaani, jaguaari, puuma, valas, valkohai, delfiini, sammakko, chinchilla, kapybara, villisika, piikkisika, kettu, susi, pöllö")
			.split(",");

	private static final String[] verbs = (
			"kaivaa, kuopii, syöttää, juottaa, kupittaa, hyppii, istuu, seisoo, laulaa, huutaa, hakkaa, raivoaa, puree, kirjoittaa, lukee, katsoo, ohjelmoi, päivittää, palauttaa, abstrahoi, maksaa, tulee, juoksee, kävelee, neppailee, kumittaa, tuijottaa, vetää, työntää, jammailee, soittelee, riehuu, avaa, korkkaa, kiipeilee, potkii, pomppii, kierii, toljottaa")
			.split(",");

	private static final String[] adjectives = (
			"ainainen, aistikas, aistillinen, aito, ajattelevainen, akateeminen, bailaava, bakteeriton, balansoiva, balleriinamainen, ballistinen, balsamoiva, charmikas, cool, diskomainen, duunaava, dynaaminen, eksoottinen, eloisa, elävä, empaattinen, fyysinen, fiksu, filmaattinen, grillimäinen, giganttinen, hajoamaton, hallitseva, hallittu, halpa, haltioitunut, haluava, ihana, identtinen, iloinen, juopunut, jalo, janoisa, joustava")
			.split(",");

	private static final Random rnd = new Random();


	/*
	 * The refineText method is used to change the message
	 * Now it is time invent something fun!
	 *
	 * In the example implementation a random work from a word list is added to the end of the message.
	 * But you do you!
	 *
	 * Please keep the message readable. No ROT13 etc, please
	 *
	 */
	public static String refineText(String inText) {
		String outText = inText;

		// Change the content of the message here.
		outText = outText + " " +
				conjunctions[rnd.nextInt(conjunctions.length)] + " " +
				adjectives[rnd.nextInt(adjectives.length)] + " " +
				animals[rnd.nextInt(animals.length)]+ " " +
				verbs[rnd.nextInt(verbs.length)];

		return outText;
	}


	/*
	 * This method changes the color. No editing needed.
	 *
	 * The color hue value is an integer between 0 and 360
	 */
	public static Integer refineColor(Integer inColor) {
		return (inColor + 20) < 360 ? (inColor + 20) : 0;
	}

}
