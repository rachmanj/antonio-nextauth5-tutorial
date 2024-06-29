import * as z from "zod";

export const LoginSchema = z.object({
  email: z.string().email({ message: "Email diperlukan" }),
  password: z.string().min(1, { message: "Password diperlukan" }),
});

export const RegisterSchema = z.object({
  email: z.string().email({ message: "Email diperlukan" }),
  password: z.string().min(6, { message: "Minimum 6 chars" }),
  name: z.string().min(1, { message: "Nama diperlukan" }),
});
