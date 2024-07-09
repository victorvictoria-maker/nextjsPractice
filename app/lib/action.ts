'use server';

import { sql } from '@vercel/postgres';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { z } from 'zod';

import { signIn } from '@/auth';
import { AuthError } from 'next-auth';
import bcrypt from 'bcrypt';
import { isRedirectError } from 'next/dist/client/components/redirect';

export async function authenticate(
  prevState: string | undefined,
  formData: FormData,
) {
  try {
    await signIn('credentials', formData);
  } catch (error) {
    if (error instanceof AuthError) {
      switch (error.type) {
        case 'CredentialsSignin':
          return 'Invalid credentials.';
        default:
          return 'Something went wrong.';
      }
    }
    throw error;
  }
}

const RegisterSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1),
  password: z.string().min(6),
  confirmPassword: z.string().min(6),
});

const Register = RegisterSchema.omit({ confirmPassword: true });
const RegisterType = Register['_output'];

const FullRegisterSchema = RegisterSchema.refine(
  (data) => data.confirmPassword === data.password,
  {
    message: 'Password does not match',
    path: ['confirmPassword'],
  },
);

export type RegisterState = {
  errors?: {
    email?: string[];
    name?: string[];
    password?: string[];
    confirmPassword?: string[];
  };
  message?: string | null;
};

async function createUser(formData: typeof RegisterType) {
  const result = await sql`
      INSERT INTO users (email, password, name)
      VALUES (${formData.email}, ${formData.password},  ${formData.name})
    `;

  return result.rowCount;
}

export async function register(
  prevState: RegisterState | undefined,
  formData: FormData,
) {
  try {
    const validatedFields = FullRegisterSchema.safeParse({
      email: formData.get('email'),
      name: formData.get('name'),
      password: formData.get('password'),
      confirmPassword: formData.get('confirm-password'),
    });

    if (!validatedFields.success) {
      return {
        errors: validatedFields.error.flatten().fieldErrors,
        message: 'Missing Fields. Failed to Create User, please try again.',
      };
    }

    const { email, password, name } = validatedFields.data;

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // create user
    const rowCount = await createUser({
      email,
      password: hashedPassword,
      name,
    });

    if (rowCount !== 1) {
      return {
        message: 'Database error. Failed to create user.',
      };
    }

    // sign in if user has been created
    await signIn('credentials', { email, password });
  } catch (error: string | any) {
    // handle user exists
    if (error.code == '23505') {
      return {
        message: 'Email already exists. Please sign in.',
      };
    }

    if (isRedirectError(error)) {
      redirect('/dashboard');
    }

    return {
      message: 'Something went wrong, please try again.',
    };
  }
}

const FormSchema = z.object({
  id: z.string(),
  customerId: z.string({
    invalid_type_error: 'Please select a customer.',
  }),
  amount: z.coerce
    .number()
    .gt(0, { message: 'Please enter an amount greater than $0.' }),
  status: z.enum(['pending', 'paid'], {
    invalid_type_error: 'Please select an invoice status.',
  }),
  date: z.string(),
});

const CreateInvoice = FormSchema.omit({ id: true, date: true });
// Use Zod to update the expected types
const UpdateInvoice = FormSchema.omit({ id: true, date: true });

export type State = {
  errors?: {
    customerId?: string[];
    amount?: string[];
    status?: string[];
  };
  message?: string | null;
};

export async function createInvoice(prevState: State, formData: FormData) {
  // Validate form using Zod
  const validatedFields = CreateInvoice.safeParse({
    customerId: formData.get('customerId'),
    amount: formData.get('amount'),
    status: formData.get('status'),
  });

  // If form validation fails, return errors early. Otherwise, continue.
  if (!validatedFields.success) {
    return {
      errors: validatedFields.error.flatten().fieldErrors,
      message: 'Missing Fields. Failed to Create Invoice.',
    };
  }

  // Prepare data for insertion into the database
  const { customerId, amount, status } = validatedFields.data;
  const amountInCents = amount * 100;
  const date = new Date().toISOString().split('T')[0];

  // Insert data into the database
  try {
    await sql`
      INSERT INTO invoices (customer_id, amount, status, date)
      VALUES (${customerId}, ${amountInCents}, ${status}, ${date})
    `;
  } catch (error) {
    // If a database error occurs, return a more specific error.
    return {
      message: 'Database Error: Failed to Create Invoice.',
    };
  }

  // Revalidate the cache for the invoices page and redirect the user.
  revalidatePath('/dashboard/invoices');
  redirect('/dashboard/invoices');
}

export async function updateInvoice(id: string, formData: FormData) {
  const { customerId, amount, status } = UpdateInvoice.parse({
    customerId: formData.get('customerId'),
    amount: formData.get('amount'),
    status: formData.get('status'),
  });

  const amountInCents = amount * 100;

  try {
    await sql`
        UPDATE invoices
        SET customer_id = ${customerId}, amount = ${amountInCents}, status = ${status}
        WHERE id = ${id}
      `;
  } catch (error) {
    return { message: 'Database Error: Failed to Update Invoice.' };
  }

  revalidatePath('/dashboard/invoices');
  redirect('/dashboard/invoices');
}

export async function deleteInvoice(id: string) {
  try {
    await sql`DELETE FROM invoices WHERE id = ${id}`;
    revalidatePath('/dashboard/invoices');
    return { message: 'Deleted Invoice.' };
  } catch (error) {
    return { message: 'Database Error: Failed to Delete Invoice.' };
  }
}
