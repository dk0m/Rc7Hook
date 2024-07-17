
# Rc7Hook

A Patchless Windows API Hooking Library.


## How Does It Work?

As the description states, Rc7Hook does **NOT** patch functions with a trampoline jump byte array, Instead, It uses both **IAT Hooking** and **EAT Hooking** to redirect the target function's address to that of our hook function.

## The 2 Methods Of Calling Api Functions

Obviously there isn't only one way to call an api function, Some people would directly call an api function in their code which would require linking, Other people may use **GetProcAddress** to fetch the function's address and call it after it has been casted to the function's prototype, Rc7Hook hooks the **IAT** of the current process so when directly calling an api function it would call the hook function, Then Rc7Hook hooks the **EAT** so that it can also change the function's address to our hook function but this time when the function's address is retrieved by calling the **GetProcAddress** api function.
