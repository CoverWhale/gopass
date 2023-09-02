# gopass

Gopass generates random passwords. 

## Usage

Gopass uses function options to build the password options.

```
random, err := gopass.NewRandomPassword(16,
      gopass.NoRepeatingCharacters(),
      gopass.IncludeNumbers(),
      gopass.IncludeLowerCase(),
      gopass.IncludeUpperCase(),
      gopass.IncludeSpecial(),
      gopass.IncludeCustom(secrets.PassChars("*@")),
)

fmt.Println(random)

```


### Characters

Custom characters can be passed in as well. This is for cases where you need a limited set of characters.

```
random, err := gopass.NewRandomPassword(16
      gopass.IncludeLowerCase(),
      gopass.IncludeCustom(secrets.PassChars("*@")),
)
```

### Verifiers

Gopass also has verify functions. A built in verify function is to ensure repeating consecutive characters
don't exist in the password. However any function that takes a string and returns a bool can be used. This
can be helpful if you need to ensure a character(s) is excluded or included.

However, the more general the inclusion/exclusion, the more likely a larger number of iterations 
will be needed.

For example to include the default special characters, but not include `$`, this can be used:

```
random, err := gopass.NewRandomPassword(16,
      gopass.IncludeLowerCase(),
      gopass.IncludeSpecial(),
      gopass.CustomVerifier(func(s string) bool {
          return !strings.Contains(s, "$")
      })
)

```

### Iterations

The number of iterations can be adjusted for when verify functions are more generic. As soon as a password
that meets all criteria is generated it is returned and iterations are stopped.

```
random, err := gopass.NewRandomPassword(16,
      gopass.IncludeLowerCase(),
      gopass.CorrectnessIterations(2000),
      gopass.CustomVerifier(func(s string) bool {
          return strings.Contains(s, "$")
      })
)
    
```
