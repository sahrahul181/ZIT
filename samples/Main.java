// Sample program used to produce a DEX for the ZIT parser/printer.
// Exercises a spread of bytecode: static + virtual methods, a loop,
// arithmetic, an object (StringBuilder), and System.out invocation.
public class Main {
    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 10;
        System.out.println("fib(" + n + ") = " + fib(n));
        System.out.println("sum(0.." + n + ") = " + sum(n));
    }

    static long fib(int n) {
        if (n < 2) return n;
        long a = 0, b = 1;
        for (int i = 2; i <= n; i++) {
            long t = a + b;
            a = b;
            b = t;
        }
        return b;
    }

    static int sum(int n) {
        int total = 0;
        for (int i = 0; i <= n; i++) total += i;
        return total;
    }

    static int factorial(int n) {
        int result = 1;
        for (int i = 1; i <= n; i++) {
            result *= i;
        }
        return result;
    }
}
