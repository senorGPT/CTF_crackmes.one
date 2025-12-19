# RodrigoTeixeira - Roullete Simulator — Reverse Engineering Write-up

**Challenge link:** https://crackmes.one/crackme/693c48822d267f28f69b8518  
**Author:** *RodrigoTeixeira*  
**Write-up by:** *SenorGPT*  
**Tools used:** *JADX*

| Platform | Difficulty | Quality | Arch | Language |
|---|---|---|---|---|
| Windows | 3.0 | 4.0 | java | Java |

---

## <center><img src="C:\Users\david\Desktop\crackmes.one\RodrigoTeixeira - Roullete Simulator\cover.png" alt="cover" style="zoom:45%;" /></center>

> **Status:** Complete  
> **Goal:** Document a clean path from initial recon → locating key-check logic → validation/reversal strategy  

---

[TOC]

---

## 1. Executive Summary

The binary seems to be some kind of game, a roulette game.
- What the binary appears to be.
- Your overall approach.
- The key outcome so far.



Running the program provides us with the following information:

- You start with 100 notes
- You are considered to have beaten the crackme if you get the note count to be negative.
- If you lose all your money - that is, if you have exactly 0 notes - the program automatically closes and you are not considered to having beaten the crackme.
- You may bet as much as you want, as long as it is a positive amount less than or equal to your current notes.
- Follows the European Roulette rules:
  - *18/37* chance of doubling the bet
  - *19/37* chance of losing the bet

- No patching, altering code, seed manipulation (IE, via System Time Adjustment), debuggers to extract the seed from memory, and using automated tools to automatically input to the *Portable Executable* (*PE*).
- Yes utilizing betting strategies such as Martingale or similar, decompiling and analysing the code, and whatever information the program provides during runtime.



---

## 2. Target Overview

### 2.1 UI / Behaviour

- Inputs:
- Outputs:
- Expected protection level:

### 2.2 Screens

#### Start-up

![image-20251219013138086](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251219013138086.png)

#### See Rules

![image-20251219013308506](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251219013308506.png)



#### Failure case

![][image2]



---

## 3. Tooling & Environment

- OS: *Windows 11*
- Other: *JDK*
- Static tools: *JADX*



---

## 4. Static Recon

Upon extracting the file from the `.rar` file it came downloaded in, I noticed that it was just a plain `.class` *Java* file. This means that it first has to be built into a `.jar` file before we can execute the code.

This requirement will be met by utilizing the `JDK`. Opening a terminal in the same directory as the `main.class` file I run the following command to convert the `.class` file into a `.jar` file.

```bash
jar cfe RouletteSimulator.jar Main Main.class
```

- `c` = create
- `f` = write to file
- `e` = set entry point (`Main-Class`)

![image-20251219012936859](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251219012936859.png)

Success, this build the `.jar` file with no error. Just to be sure I run the newly created `.jar` file with the following command:

```bash
java -jar ./RouletteSimulator.jar
```

![image-20251219013055270](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251219013055270.png)

Amazing!



### 4.1 Source Code

My first approach is to start analysing the source code to see if I can see any clear or obvious logical bugs I could exploit. *BUT*, before I get to that, I decide to poke the binary a bit with some [Dynamic Analysis](##5. Dynamic Analysis).

```java
// Source code is decompiled from a .class file using FernFlower decompiler (from Intellij IDEA).
import java.util.InputMismatchException;
import java.util.Scanner;

public class Main {
   private int seed;
   byte DecompilingJavaCodeIsReallyEasyIsntIt;

   public Main() {
      System.out.println("Welcome to this crackme by Rodrigo Teixeira from Portugal.\n\nThis is a roullete simulator.\n\nYou start with 100 money units and you are considered to\nhave beaten the crackme if you get negative money.\n\nIf you lose all your money (that is, if you have exactly 0 money units),\nthe program automatically closes and you are not considered to having beaten the crackme.\n\nYou may bet as much as you want, as long as it is a positive ammount\nless than or equal to your current money.\n\nThis follows the European Roullete rules, that is, 18/37 chance of doubling the bet,\nand 19/37 chance of losing the bet.\n\nGood luck!\n\n");
      this.seed = (int)System.nanoTime() & '\uffff';
      Scanner var1 = new Scanner(System.in);

      try {
         System.out.print("See rules? [Y]es/[N]o: ");
         String var2 = var1.nextLine();
         if (!var2.isEmpty() && var2.toLowerCase().charAt(0) == 'y') {
            System.out.println("\nYou are not allowed to do the following:\n\n1 -> Decompile, alter the code, and recompiling a modified version of the code.\n2 -> Manipulating the system clock in any way ir order to obtain control over the initial RNG seed choice.\n3 -> Using debug RAM watch or any other way to extract the seed value from memory.\n4 -> Using automated tools to automaticly input to this program (exception: manually copy-pasting text).\n\nYou are allowed to do the following:\n\n1 -> Using betting strategies such as martingale or similar.\n2 -> Decompiling and analysing the code in any way. The code is not obfuscated.\nUsing the information that the program gives you at runtime in any way of you likings.");
         }

         int var3 = 100;
         System.out.println("\n\nMoney: " + var3);

         while(true) {
            if (var3 <= 0) {
               if (var3 < 0) {
                  System.out.println("Congratulations, you solved the crackme!\n\nPress Enter to Exit.");
                  var1.nextLine();
               }
               break;
            }

            int var4 = -1;

            do {
               try {
                  System.out.print("Enter bet: ");
                  var4 = var1.nextInt();
               } catch (InputMismatchException var7) {
                  System.out.println("Please Input a valid 32-bit integer.");
               }
            } while(var4 < 1 || var4 > var3);

            if (this.rand() % 37 < 18) {
               var3 += var4;
            } else {
               var3 -= var4;
            }

            System.out.println("Money: " + var3);
         }
      } catch (Throwable var8) {
         try {
            var1.close();
         } catch (Throwable var6) {
            var8.addSuppressed(var6);
         }

         throw var8;
      }

      var1.close();
   }

   private int rand() {
      this.seed ^= this.seed << 7 & '\uffff';
      this.seed ^= this.seed >>> 9;
      this.seed ^= this.seed << 8 & '\uffff';
      return this.seed;
   }

   public static void main(String[] var0) {
      new Main();
   }
}

```

Upon program initialization, it defines a global variable `seed` and assigns it the result of the following operation upon entering `Main`.

```java
this.seed = ((int) System.nanoTime()) & 65535;
```

So `seed` is effectively *16-bits* : 0-65535.

It appears that the main logic of the roulette game resides within the `while` loop.

```java
while (i > 0) {
    int iNextInt = -1;
    while (true) {
        try {
            System.out.print("Enter bet: ");
            iNextInt = scanner.nextInt();
        } catch (InputMismatchException e) {
            System.out.println("Please Input a valid 32-bit integer.");
        }
        if (iNextInt >= 1 && iNextInt <= i) {
            break;
        }
    }
    if (rand() % 37 < 18) {
        i += iNextInt;
    } else {
        i -= iNextInt;
    }
    System.out.println("Money: " + i);
}
```



Which utilizes its own `rand` method to manipulate the `seed` global.

```java
private int rand() {
    this.seed ^= (this.seed << 7) & 65535;
    this.seed ^= this.seed >>> 9;
    this.seed ^= (this.seed << 8) & 65535;
    return this.seed;
}
```

`rand() % 37 < 18` decides win/lose:

- **Win** if `(rand() % 37) ∈ [0..17]`
- **Lose** otherwise.



After quite some pondering I deduce the following. The balance `i` can never go negative. You either wander around > 0, or eventually hit `i = 0` and exit. So there is no **pure betting strategy** (*Martingale*, etc.) that guarantees `i < 0`. The only way to go negative is **integer overflow**. Recall that the max signed 32-bit int = `2,147,483,647` (= `0x7FFFFFFF`). If `i` and `bet` get large enough they will overflow and enter the win condition.





---

### 4.2 Analysing the Rules

Given the rules:

- Start: **100 notes**
- On each bet of size `b`:
  - Win: `notes += b` with prob **18/37**
  - Lose: `notes -= b` with prob **19/37**
- You must always bet `0 < b ≤ notes`
- If `notes == 0`, the program **exits**
- You “win the crackme” only if `notes < 0`

Key observation, **You can’t cross 0 if the code really enforces `b ≤ notes`.**

- If `notes > 0` and you lose, new notes = `notes - b ≥ 0`.
-  If you win, notes stays > 0.

 So with those rules, a perfect implementation *never* reaches a negative balance. Therefore, **it’s mathematically impossible to guarantee a negative balance**. That’s the big hint: the “solution” is almost certainly about **finding a bug in the Java code**, not about being clever with Roulette strategies.



---

## 5. Dynamic Analysis

Before looking at code, I attempt poking it with weird inputs manually:

- Trying a *positive whole number*.
  ![image-20251219015131312](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251219015131312.png)

  ------

- Trying *zero.*
  ![image-20251219014806640](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251219014806640.png)

------

- Trying a *negative number*.
  ![image-20251219015004268](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251219015004268.png)

  ------

- Trying an *extremely large number* - value greater than a *signed 32-bit* max value limit.
  ![image-20251219015533086](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251219015533086.png)
  Causes this prompt to be output to console on repeat for what seems indefinitely.

  ------

- Trying a *positive & negative decimal number*.
  Same effect as above with an *extremely large number*.

  ------

- Trying junk like *1e9* & *helloworld*.
  Same effect as above with an *extremely large number* and *positive & negative decimal numbers*.

  ------

- Trying *spamming Enter*.
  ![image-20251219020020430](C:\Users\david\AppData\Roaming\Typora\typora-user-images\image-20251219020020430.png)

  Doesn't parse the input.



No immediate weird behaviour was observed. Following this observation, I continue on back to the [Source Code](###4.1 Source Code) in order to attempt to find any bugs within the source code.



---

## 6. Getting Gud

So the plan:

1. **Reverse the Pseudorandom Number Generator (PRNG) and win/lose mapping** (we already have the code).
2. **Interact with the crackme with small bets**, recording the win/lose pattern.
3. **Offline, brute-force all 65536 possible seeds** to see which seed(s) produce that exact pattern.
4. Once you know the current seed/state, **predict all future win/lose outcomes**.
5. Use that prediction to:
   - bet **1** when a loss is coming
   - bet **everything (`i`)** when a win is coming
      so your money grows ~exponentially.
6. Keep going until `i` gets huge and a predicted win will overflow it past `2,147,483,647` into negative.

That hits the “negative notes” victory condition without breaking any of the author’s rules.







---

## 7. Findings Log



---

## 8. Conclusion

- Summary of final understanding.
- What you’d improve next time.
- Optional lessons learned.
