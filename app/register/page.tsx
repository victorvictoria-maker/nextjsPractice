import AcmeLogo from '@/app/ui/acme-logo';
import RegisterForm from '../ui/register-form';

import { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Register',
};

export default function RegisterPage() {
  return (
    <main className="flex h-full items-center justify-center">
      <div className="relative mx-auto flex w-full max-w-[400px] flex-col space-y-2.5 p-4 md:-mt-32">
        <div className="flex h-20 w-full items-end rounded-lg bg-blue-500 p-3 md:h-36">
          <div className="w-32 text-white md:w-36">
            <AcmeLogo />
          </div>
        </div>
        <RegisterForm />
      </div>
    </main>
  );
}
