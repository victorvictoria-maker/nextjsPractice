import { fetchFilteredCustomers } from '@/app/lib/data';
import CustomersTable from '@/app/ui/customers/table';
import { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Customers',
};

export default async function Page({
  searchParams,
}: {
  searchParams: {
    query?: string;
  };
}) {
  const query = searchParams.query || '';

  const customers = await fetchFilteredCustomers(query);

  return <CustomersTable customers={customers} />;
}
